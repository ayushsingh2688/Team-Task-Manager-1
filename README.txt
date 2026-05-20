Team Task Manager (Full-Stack)

Live Application URL:
Add your Railway live URL after deployment.

GitHub Repository Link:
Add your GitHub repository URL after pushing the project.

Overview:
Team Task Manager is a full-stack web app for creating projects, assigning tasks, tracking progress, and enforcing role-based access control for Admin and Member users.

Features:
- Signup and login authentication with hashed passwords and session tokens.
- Role-based access control:
  - Admin can create, update, and delete projects.
  - Admin can create, assign, update, and delete tasks.
  - Admin can see the team list.
  - Member can view accessible projects/tasks and update the status of their own assigned tasks.
- Public signup creates Member accounts; seeded Admin credentials are provided for administrative access.
- Project and team management with project members.
- Task creation, assignment, status tracking, priority, and due dates.
- Dashboard with total projects, tasks, in-progress tasks, overdue tasks, project progress, and upcoming tasks.
- REST API backend.
- Persistent NoSQL-style JSON database stored in data/db.json.
- Server-side validations and relationship checks between users, projects, and tasks.

Tech Stack:
- Frontend: HTML, CSS, JavaScript
- Backend: Node.js HTTP server
- Database: File-backed JSON NoSQL-style database
- Deployment: Railway-ready with railway.json and npm start script

Demo Credentials:
- Admin: admin@example.com / Admin@123
- Member: member@example.com / Member@123
- Member: designer@example.com / Member@123

How to Run Locally:
1. Install Node.js 20 or newer.
2. Open the project folder.
3. Run:
   npm start
4. Open:
   http://localhost:3000

REST API Endpoints:
- POST /api/auth/signup
- POST /api/auth/login
- POST /api/auth/logout
- GET /api/me
- GET /api/dashboard
- GET /api/users
- GET /api/projects
- POST /api/projects
- GET /api/projects/:id
- PUT /api/projects/:id
- DELETE /api/projects/:id
- GET /api/tasks
- POST /api/tasks
- PUT /api/tasks/:id
- DELETE /api/tasks/:id

Railway Deployment:
1. Push this project to a GitHub repository.
2. Create a new Railway project.
3. Choose "Deploy from GitHub repo".
4. Select this repository.
5. Railway will use npm start from package.json.
6. After deployment, copy the generated Railway domain and paste it as the Live Application URL.

Notes:
- The app is fully functional without external packages.
- data/db.json is created automatically on the first server start with seed users, projects, and tasks.
- For production-scale usage, the same REST structure can be connected to PostgreSQL or MongoDB.
