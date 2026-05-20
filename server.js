const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "db.json");
const PUBLIC_DIR = path.join(__dirname, "public");
const MAX_BODY_BYTES = 1024 * 1024;
const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 7;

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

function nowIso() {
  return new Date().toISOString();
}

function randomId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(password, salt, 120000, 32, "sha256").toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, expected] = String(stored || "").split(":");
  if (!salt || !expected) return false;
  const actual = crypto.pbkdf2Sync(password, salt, 120000, 32, "sha256").toString("hex");
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function ensureDatabase() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (fs.existsSync(DB_PATH)) return;

  const adminId = randomId("usr");
  const memberId = randomId("usr");
  const designerId = randomId("usr");
  const projectId = randomId("prj");
  const today = new Date();
  const soon = new Date(today.getTime() + 1000 * 60 * 60 * 24 * 5);
  const later = new Date(today.getTime() + 1000 * 60 * 60 * 24 * 12);
  const overdue = new Date(today.getTime() - 1000 * 60 * 60 * 24 * 2);

  const db = {
    users: [
      {
        id: adminId,
        name: "Aarav Admin",
        email: "admin@example.com",
        role: "admin",
        passwordHash: hashPassword("Admin@123"),
        createdAt: nowIso()
      },
      {
        id: memberId,
        name: "Maya Member",
        email: "member@example.com",
        role: "member",
        passwordHash: hashPassword("Member@123"),
        createdAt: nowIso()
      },
      {
        id: designerId,
        name: "Kabir Designer",
        email: "designer@example.com",
        role: "member",
        passwordHash: hashPassword("Member@123"),
        createdAt: nowIso()
      }
    ],
    projects: [
      {
        id: projectId,
        name: "Launch Planning Board",
        description: "Coordinate product launch tasks, owners, reviews, and delivery dates.",
        ownerId: adminId,
        memberIds: [memberId, designerId],
        dueDate: later.toISOString().slice(0, 10),
        createdAt: nowIso(),
        updatedAt: nowIso()
      }
    ],
    tasks: [
      {
        id: randomId("tsk"),
        projectId,
        title: "Create launch checklist",
        description: "List every launch dependency and assign a clear owner.",
        assignedTo: memberId,
        status: "todo",
        priority: "high",
        dueDate: soon.toISOString().slice(0, 10),
        createdBy: adminId,
        createdAt: nowIso(),
        updatedAt: nowIso()
      },
      {
        id: randomId("tsk"),
        projectId,
        title: "Prepare landing page assets",
        description: "Export final product screenshots and illustrations for the landing page.",
        assignedTo: designerId,
        status: "in-progress",
        priority: "medium",
        dueDate: overdue.toISOString().slice(0, 10),
        createdBy: adminId,
        createdAt: nowIso(),
        updatedAt: nowIso()
      },
      {
        id: randomId("tsk"),
        projectId,
        title: "Review release notes",
        description: "Check final copy for clarity before publishing.",
        assignedTo: memberId,
        status: "done",
        priority: "low",
        dueDate: today.toISOString().slice(0, 10),
        createdBy: adminId,
        createdAt: nowIso(),
        updatedAt: nowIso()
      }
    ],
    sessions: []
  };

  writeDb(db);
}

function readDb() {
  ensureDatabase();
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt
  };
}

function sanitizeProject(project, tasks) {
  const related = tasks.filter((task) => task.projectId === project.id);
  const completed = related.filter((task) => task.status === "done").length;
  return {
    ...project,
    taskCount: related.length,
    completedTaskCount: completed,
    progress: related.length ? Math.round((completed / related.length) * 100) : 0
  };
}

function sanitizeTask(task, db) {
  const project = db.projects.find((item) => item.id === task.projectId);
  const assignee = db.users.find((item) => item.id === task.assignedTo);
  const creator = db.users.find((item) => item.id === task.createdBy);
  return {
    ...task,
    projectName: project ? project.name : "Unknown project",
    assigneeName: assignee ? assignee.name : "Unassigned",
    createdByName: creator ? creator.name : "Unknown"
  };
}

function canAccessProject(user, project, db) {
  if (!user || !project) return false;
  if (user.role === "admin") return true;
  return project.memberIds.includes(user.id) || db.tasks.some((task) => task.projectId === project.id && task.assignedTo === user.id);
}

function canAccessTask(user, task, db) {
  if (!user || !task) return false;
  if (user.role === "admin") return true;
  const project = db.projects.find((item) => item.id === task.projectId);
  return task.assignedTo === user.id || canAccessProject(user, project, db);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > MAX_BODY_BYTES) {
        reject(apiError(413, "Request body is too large."));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(apiError(400, "Invalid JSON request body."));
      }
    });
    req.on("error", () => reject(apiError(400, "Unable to read request body.")));
  });
}

function apiError(status, message, details) {
  const error = new Error(message);
  error.status = status;
  error.details = details;
  return error;
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  res.end(JSON.stringify(payload));
}

function notFound(res) {
  sendJson(res, 404, { error: "Not found." });
}

function methodNotAllowed(res) {
  sendJson(res, 405, { error: "Method not allowed." });
}

function requireFields(body, fields) {
  const missing = fields.filter((field) => !String(body[field] || "").trim());
  if (missing.length) {
    throw apiError(422, "Required fields are missing.", { fields: missing });
  }
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function assertEmail(email) {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw apiError(422, "Please enter a valid email address.");
  }
}

function assertPassword(password) {
  if (String(password || "").length < 6) {
    throw apiError(422, "Password must be at least 6 characters long.");
  }
}

function assertDate(date, fieldName) {
  if (!date) return;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(`${date}T00:00:00Z`))) {
    throw apiError(422, `${fieldName} must be a valid YYYY-MM-DD date.`);
  }
}

function getAuthUser(req, db) {
  const auth = req.headers.authorization || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;

  const session = db.sessions.find((item) => item.tokenHash === tokenHash(match[1]) && Date.parse(item.expiresAt) > Date.now());
  if (!session) return null;
  return db.users.find((user) => user.id === session.userId) || null;
}

function requireAuth(req, db) {
  const user = getAuthUser(req, db);
  if (!user) throw apiError(401, "Please login to continue.");
  return user;
}

function requireAdmin(user) {
  if (user.role !== "admin") throw apiError(403, "Admin access is required for this action.");
}

function cleanExpiredSessions(db) {
  const before = db.sessions.length;
  db.sessions = db.sessions.filter((session) => Date.parse(session.expiresAt) > Date.now());
  return db.sessions.length !== before;
}

function routeParts(req) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  return {
    pathname: url.pathname,
    parts: url.pathname.split("/").filter(Boolean),
    query: url.searchParams
  };
}

function dashboardFor(user, db) {
  const visibleTasks = db.tasks.filter((task) => canAccessTask(user, task, db));
  const visibleProjects = db.projects.filter((project) => canAccessProject(user, project, db));
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const stats = {
    totalProjects: visibleProjects.length,
    totalTasks: visibleTasks.length,
    todoTasks: visibleTasks.filter((task) => task.status === "todo").length,
    inProgressTasks: visibleTasks.filter((task) => task.status === "in-progress").length,
    completedTasks: visibleTasks.filter((task) => task.status === "done").length,
    overdueTasks: visibleTasks.filter((task) => task.status !== "done" && Date.parse(`${task.dueDate}T00:00:00`) < today.getTime()).length,
    members: user.role === "admin" ? db.users.length : visibleProjects.reduce((ids, project) => {
      project.memberIds.forEach((id) => ids.add(id));
      return ids;
    }, new Set([user.id])).size
  };

  const byStatus = ["todo", "in-progress", "done"].map((status) => ({
    status,
    count: visibleTasks.filter((task) => task.status === status).length
  }));

  const upcoming = visibleTasks
    .filter((task) => task.status !== "done")
    .sort((a, b) => String(a.dueDate).localeCompare(String(b.dueDate)))
    .slice(0, 6)
    .map((task) => sanitizeTask(task, db));

  return {
    stats,
    byStatus,
    upcoming,
    projects: visibleProjects.map((project) => sanitizeProject(project, visibleTasks))
  };
}

async function handleApi(req, res) {
  const db = readDb();
  let didMutate = cleanExpiredSessions(db);
  const { parts, query } = routeParts(req);

  try {
    if (parts[1] === "auth" && parts[2] === "signup") {
      if (req.method !== "POST") return methodNotAllowed(res);
      const body = await parseBody(req);
      requireFields(body, ["name", "email", "password"]);
      const email = normalizeEmail(body.email);
      assertEmail(email);
      assertPassword(body.password);
      const role = db.users.length === 0 ? "admin" : "member";
      if (db.users.some((user) => user.email === email)) {
        throw apiError(409, "An account with this email already exists.");
      }
      const user = {
        id: randomId("usr"),
        name: String(body.name).trim(),
        email,
        role,
        passwordHash: hashPassword(body.password),
        createdAt: nowIso()
      };
      db.users.push(user);
      didMutate = true;
      const token = crypto.randomBytes(32).toString("hex");
      db.sessions.push({
        id: randomId("ses"),
        userId: user.id,
        tokenHash: tokenHash(token),
        createdAt: nowIso(),
        expiresAt: new Date(Date.now() + TOKEN_TTL_MS).toISOString()
      });
      writeDb(db);
      return sendJson(res, 201, { user: publicUser(user), token });
    }

    if (parts[1] === "auth" && parts[2] === "login") {
      if (req.method !== "POST") return methodNotAllowed(res);
      const body = await parseBody(req);
      requireFields(body, ["email", "password"]);
      const email = normalizeEmail(body.email);
      const user = db.users.find((item) => item.email === email);
      if (!user || !verifyPassword(String(body.password), user.passwordHash)) {
        throw apiError(401, "Invalid email or password.");
      }
      const token = crypto.randomBytes(32).toString("hex");
      db.sessions.push({
        id: randomId("ses"),
        userId: user.id,
        tokenHash: tokenHash(token),
        createdAt: nowIso(),
        expiresAt: new Date(Date.now() + TOKEN_TTL_MS).toISOString()
      });
      writeDb(db);
      return sendJson(res, 200, { user: publicUser(user), token });
    }

    if (parts[1] === "auth" && parts[2] === "logout") {
      if (req.method !== "POST") return methodNotAllowed(res);
      const auth = req.headers.authorization || "";
      const token = auth.match(/^Bearer\s+(.+)$/i)?.[1];
      if (token) {
        db.sessions = db.sessions.filter((session) => session.tokenHash !== tokenHash(token));
        writeDb(db);
      } else if (didMutate) {
        writeDb(db);
      }
      return sendJson(res, 200, { ok: true });
    }

    const user = requireAuth(req, db);

    if (parts[1] === "me" && parts.length === 2) {
      if (req.method !== "GET") return methodNotAllowed(res);
      if (didMutate) writeDb(db);
      return sendJson(res, 200, { user: publicUser(user) });
    }

    if (parts[1] === "dashboard" && parts.length === 2) {
      if (req.method !== "GET") return methodNotAllowed(res);
      if (didMutate) writeDb(db);
      return sendJson(res, 200, dashboardFor(user, db));
    }

    if (parts[1] === "users" && parts.length === 2) {
      if (req.method !== "GET") return methodNotAllowed(res);
      if (didMutate) writeDb(db);
      return sendJson(res, 200, {
        users: db.users.map(publicUser).sort((a, b) => a.name.localeCompare(b.name))
      });
    }

    if (parts[1] === "projects" && parts.length === 2) {
      if (req.method === "GET") {
        const projects = db.projects
          .filter((project) => canAccessProject(user, project, db))
          .map((project) => sanitizeProject(project, db.tasks));
        if (didMutate) writeDb(db);
        return sendJson(res, 200, { projects });
      }

      if (req.method === "POST") {
        requireAdmin(user);
        const body = await parseBody(req);
        requireFields(body, ["name", "dueDate"]);
        assertDate(body.dueDate, "Project due date");
        const memberIds = Array.isArray(body.memberIds) ? body.memberIds : [];
        const invalidMembers = memberIds.filter((id) => !db.users.some((member) => member.id === id));
        if (invalidMembers.length) throw apiError(422, "One or more selected members do not exist.");
        const project = {
          id: randomId("prj"),
          name: String(body.name).trim(),
          description: String(body.description || "").trim(),
          ownerId: user.id,
          memberIds: [...new Set(memberIds)],
          dueDate: body.dueDate,
          createdAt: nowIso(),
          updatedAt: nowIso()
        };
        db.projects.push(project);
        writeDb(db);
        return sendJson(res, 201, { project: sanitizeProject(project, db.tasks) });
      }

      return methodNotAllowed(res);
    }

    if (parts[1] === "projects" && parts.length === 3) {
      const project = db.projects.find((item) => item.id === parts[2]);
      if (!project) return notFound(res);

      if (req.method === "GET") {
        if (!canAccessProject(user, project, db)) throw apiError(403, "You do not have access to this project.");
        if (didMutate) writeDb(db);
        return sendJson(res, 200, {
          project: sanitizeProject(project, db.tasks),
          tasks: db.tasks.filter((task) => task.projectId === project.id && canAccessTask(user, task, db)).map((task) => sanitizeTask(task, db))
        });
      }

      if (req.method === "PUT") {
        requireAdmin(user);
        const body = await parseBody(req);
        if (body.name !== undefined && !String(body.name).trim()) throw apiError(422, "Project name is required.");
        if (body.dueDate !== undefined) assertDate(body.dueDate, "Project due date");
        if (body.memberIds !== undefined) {
          if (!Array.isArray(body.memberIds)) throw apiError(422, "Members must be an array.");
          const invalidMembers = body.memberIds.filter((id) => !db.users.some((member) => member.id === id));
          if (invalidMembers.length) throw apiError(422, "One or more selected members do not exist.");
          project.memberIds = [...new Set(body.memberIds)];
        }
        if (body.name !== undefined) project.name = String(body.name).trim();
        if (body.description !== undefined) project.description = String(body.description || "").trim();
        if (body.dueDate !== undefined) project.dueDate = body.dueDate;
        project.updatedAt = nowIso();
        writeDb(db);
        return sendJson(res, 200, { project: sanitizeProject(project, db.tasks) });
      }

      if (req.method === "DELETE") {
        requireAdmin(user);
        db.projects = db.projects.filter((item) => item.id !== project.id);
        db.tasks = db.tasks.filter((task) => task.projectId !== project.id);
        writeDb(db);
        return sendJson(res, 200, { ok: true });
      }

      return methodNotAllowed(res);
    }

    if (parts[1] === "tasks" && parts.length === 2) {
      if (req.method === "GET") {
        const status = query.get("status");
        const projectId = query.get("projectId");
        let tasks = db.tasks.filter((task) => canAccessTask(user, task, db));
        if (status) tasks = tasks.filter((task) => task.status === status);
        if (projectId) tasks = tasks.filter((task) => task.projectId === projectId);
        if (didMutate) writeDb(db);
        return sendJson(res, 200, { tasks: tasks.map((task) => sanitizeTask(task, db)) });
      }

      if (req.method === "POST") {
        requireAdmin(user);
        const body = await parseBody(req);
        requireFields(body, ["projectId", "title", "assignedTo", "dueDate"]);
        const project = db.projects.find((item) => item.id === body.projectId);
        if (!project) throw apiError(422, "Selected project does not exist.");
        const assignee = db.users.find((item) => item.id === body.assignedTo);
        if (!assignee) throw apiError(422, "Selected assignee does not exist.");
        assertDate(body.dueDate, "Task due date");
        const status = ["todo", "in-progress", "done"].includes(body.status) ? body.status : "todo";
        const priority = ["low", "medium", "high"].includes(body.priority) ? body.priority : "medium";
        if (!project.memberIds.includes(assignee.id)) project.memberIds.push(assignee.id);
        const task = {
          id: randomId("tsk"),
          projectId: project.id,
          title: String(body.title).trim(),
          description: String(body.description || "").trim(),
          assignedTo: assignee.id,
          status,
          priority,
          dueDate: body.dueDate,
          createdBy: user.id,
          createdAt: nowIso(),
          updatedAt: nowIso()
        };
        db.tasks.push(task);
        project.updatedAt = nowIso();
        writeDb(db);
        return sendJson(res, 201, { task: sanitizeTask(task, db) });
      }

      return methodNotAllowed(res);
    }

    if (parts[1] === "tasks" && parts.length === 3) {
      const task = db.tasks.find((item) => item.id === parts[2]);
      if (!task) return notFound(res);
      if (!canAccessTask(user, task, db)) throw apiError(403, "You do not have access to this task.");

      if (req.method === "PUT") {
        const body = await parseBody(req);
        const project = db.projects.find((item) => item.id === task.projectId);

        if (user.role !== "admin") {
          const allowed = Object.keys(body).every((key) => ["status"].includes(key));
          if (!allowed || task.assignedTo !== user.id) {
            throw apiError(403, "Members can only update the status of their own assigned tasks.");
          }
        }

        if (body.title !== undefined) {
          if (!String(body.title).trim()) throw apiError(422, "Task title is required.");
          task.title = String(body.title).trim();
        }
        if (body.description !== undefined) task.description = String(body.description || "").trim();
        if (body.status !== undefined) {
          if (!["todo", "in-progress", "done"].includes(body.status)) throw apiError(422, "Invalid task status.");
          task.status = body.status;
        }
        if (body.priority !== undefined) {
          if (!["low", "medium", "high"].includes(body.priority)) throw apiError(422, "Invalid priority.");
          task.priority = body.priority;
        }
        if (body.dueDate !== undefined) {
          assertDate(body.dueDate, "Task due date");
          task.dueDate = body.dueDate;
        }
        if (body.assignedTo !== undefined) {
          requireAdmin(user);
          const assignee = db.users.find((item) => item.id === body.assignedTo);
          if (!assignee) throw apiError(422, "Selected assignee does not exist.");
          task.assignedTo = assignee.id;
          if (project && !project.memberIds.includes(assignee.id)) project.memberIds.push(assignee.id);
        }
        task.updatedAt = nowIso();
        if (project) project.updatedAt = nowIso();
        writeDb(db);
        return sendJson(res, 200, { task: sanitizeTask(task, db) });
      }

      if (req.method === "DELETE") {
        requireAdmin(user);
        db.tasks = db.tasks.filter((item) => item.id !== task.id);
        writeDb(db);
        return sendJson(res, 200, { ok: true });
      }

      return methodNotAllowed(res);
    }

    if (didMutate) writeDb(db);
    return notFound(res);
  } catch (error) {
    if (didMutate) writeDb(db);
    const status = error.status || 500;
    const payload = { error: status === 500 ? "Something went wrong." : error.message };
    if (error.details) payload.details = error.details;
    if (status === 500) console.error(error);
    return sendJson(res, status, payload);
  }
}

function serveStatic(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === "/") pathname = "/index.html";

  const requested = path.normalize(path.join(PUBLIC_DIR, pathname));
  const relativePath = path.relative(PUBLIC_DIR, requested);
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    res.writeHead(403);
    return res.end("Forbidden");
  }

  fs.readFile(requested, (error, content) => {
    if (error) {
      fs.readFile(path.join(PUBLIC_DIR, "index.html"), (fallbackError, fallbackContent) => {
        if (fallbackError) {
          res.writeHead(404);
          return res.end("Not found");
        }
        res.writeHead(200, { "Content-Type": MIME_TYPES[".html"] });
        return res.end(fallbackContent);
      });
      return;
    }

    const ext = path.extname(requested);
    res.writeHead(200, {
      "Content-Type": MIME_TYPES[ext] || "application/octet-stream"
    });
    res.end(content);
  });
}

const server = http.createServer((req, res) => {
  if (req.url.startsWith("/api/")) {
    handleApi(req, res);
    return;
  }
  serveStatic(req, res);
});

server.listen(PORT, () => {
  ensureDatabase();
  console.log(`Team Task Manager running on http://localhost:${PORT}`);
});
