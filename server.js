const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, User, Project, Task } = require('./database/setup');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// ----------------- JWT AUTH -----------------
function authenticateJWT(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Missing or invalid token" });
    }
    const token = header.split(" ")[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // decoded contains id, name, email, role
        next();
    } catch (err) {
        return res.status(401).json({ error: "Invalid or expired token" });
    }
}

// ----------------- ROLE MIDDLEWARE -----------------
function requireManager(req, res, next) {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (req.user.role === "manager" || req.user.role === "admin") return next();
    return res.status(403).json({ error: "Managers or admins only" });
}

function requireAdmin(req, res, next) {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (req.user.role === "admin") return next();
    return res.status(403).json({ error: "Admins only" });
}

// ----------------- TEST DATABASE CONNECTION -----------------
async function testConnection() {
    try {
        await db.authenticate();
        console.log("Database connected.");
    } catch (err) {
        console.error("Database connection error:", err);
    }
}
testConnection();

// ----------------- AUTH ROUTES -----------------

// REGISTER
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role = "employee" } = req.body;

        const exists = await User.findOne({ where: { email } });
        if (exists) return res.status(400).json({ error: "Email already exists" });

        const hashed = await bcrypt.hash(password, 10);

        const newUser = await User.create({ name, email, password: hashed, role });

        const token = jwt.sign(
            { id: newUser.id, name, email, role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.status(201).json({ message: "Registration successful", token, user: { id: newUser.id, name, email, role } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Registration failed" });
    }
});

// LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(401).json({ error: "Invalid credentials" });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign(
            { id: user.id, name: user.name, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({ message: "Login successful", token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ error: "Login failed" });
    }
});

// LOGOUT (stateless)
app.post('/api/logout', (req, res) => res.json({ message: "Logout successful (JWT stateless)" }));

// ----------------- USER ROUTES -----------------

// PROFILE
app.get('/api/users/profile', authenticateJWT, async (req, res) => {
    const user = await User.findByPk(req.user.id, { attributes: ['id', 'name', 'email', 'role'] });
    res.json(user);
});

// ADMIN: GET ALL USERS
app.get('/api/users', authenticateJWT, requireAdmin, async (req, res) => {
    const users = await User.findAll({ attributes: ['id', 'name', 'email', 'role'] });
    res.json(users);
});

// ----------------- PROJECT ROUTES -----------------

// GET PROJECTS
app.get('/api/projects', authenticateJWT, async (req, res) => {
    const projects = await Project.findAll({ include: [{ model: User, as: 'manager', attributes: ['id', 'name', 'email'] }] });
    res.json(projects);
});

// GET SINGLE PROJECT
app.get('/api/projects/:id', authenticateJWT, async (req, res) => {
    const project = await Project.findByPk(req.params.id, {
        include: [
            { model: User, as: 'manager', attributes: ['id', 'name', 'email'] },
            { model: Task, include: [{ model: User, as: 'assignedUser', attributes: ['id', 'name', 'email'] }] }
        ]
    });
    if (!project) return res.status(404).json({ error: "Project not found" });
    res.json(project);
});

// CREATE PROJECT (Manager+)
app.post('/api/projects', authenticateJWT, requireManager, async (req, res) => {
    const { name, description, status = "active" } = req.body;
    const project = await Project.create({ name, description, status, managerId: req.user.id });
    res.status(201).json(project);
});

// UPDATE PROJECT (Manager+)
app.put('/api/projects/:id', authenticateJWT, requireManager, async (req, res) => {
    const project = await Project.findByPk(req.params.id);
    if (!project) return res.status(404).json({ error: "Project not found" });
    await project.update(req.body);
    res.json(project);
});

// DELETE PROJECT (Admin)
app.delete('/api/projects/:id', authenticateJWT, requireAdmin, async (req, res) => {
    const deleted = await Project.destroy({ where: { id: req.params.id } });
    if (!deleted) return res.status(404).json({ error: "Project not found" });
    res.json({ message: "Project deleted" });
});

// ----------------- TASK ROUTES -----------------

// GET TASKS FOR PROJECT
app.get('/api/projects/:id/tasks', authenticateJWT, async (req, res) => {
    const tasks = await Task.findAll({ where: { projectId: req.params.id }, include: [{ model: User, as: 'assignedUser', attributes: ['id', 'name', 'email'] }] });
    res.json(tasks);
});

// CREATE TASK (Manager+)
app.post('/api/projects/:id/tasks', authenticateJWT, requireManager, async (req, res) => {
    const { title, description, assignedUserId, priority = 'medium' } = req.body;
    const task = await Task.create({ title, description, projectId: req.params.id, assignedUserId, priority, status: 'pending' });
    res.status(201).json(task);
});

// UPDATE TASK (any user)
app.put('/api/tasks/:id', authenticateJWT, async (req, res) => {
    const task = await Task.findByPk(req.params.id);
    if (!task) return res.status(404).json({ error: "Task not found" });
    await task.update(req.body);
    res.json(task);
});

// DELETE TASK (Manager+)
app.delete('/api/tasks/:id', authenticateJWT, requireManager, async (req, res) => {
    const deleted = await Task.destroy({ where: { id: req.params.id } });
    if (!deleted) return res.status(404).json({ error: "Task not found" });
    res.json({ message: "Task deleted" });
});

// ----------------- START SERVER -----------------
app.listen(PORT, () => console.log('Server running at http://localhost:${PORT}'));