const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { db, User, Project, Task } = require('./database/setup');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ----------------- MIDDLEWARE -----------------
app.use(express.json());
app.use(cors());

app.use(session({
    secret: process.env.SESSION_SECRET || 'defaultsecret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// ----------------- AUTH MIDDLEWARE -----------------
function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        req.user = {
            id: req.session.userId,
            name: req.session.userName,
            email: req.session.userEmail
        };
        next();
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
}

// ----------------- HEALTH CHECK -----------------
app.get('/api/health', (req, res) => {
    res.json({ status: 'API running', env: process.env.NODE_ENV || 'development' });
});

// ----------------- AUTH ROUTES -----------------
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) return res.status(400).json({ error: 'User with this email already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({ name, email, password: hashedPassword });

        res.status(201).json({ message: 'User registered', user: { id: newUser.id, name: newUser.name, email: newUser.email } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(401).json({ error: 'Invalid email or password' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid email or password' });

        req.session.userId = user.id;
        req.session.userName = user.name;
        req.session.userEmail = user.email;

        res.json({ message: 'Login successful', user: { id: user.id, name: user.name, email: user.email } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to login' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: 'Failed to logout' });
        res.json({ message: 'Logout successful' });
    });
});

// ----------------- USER ROUTES -----------------
app.get('/api/users/profile', requireAuth, async (req, res) => {
    const user = await User.findByPk(req.user.id, { attributes: ['id','name','email'] });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
});

app.get('/api/users', requireAuth, async (req, res) => {
    const users = await User.findAll({ attributes: ['id','name','email'] });
    res.json(users);
});

// ----------------- PROJECT ROUTES -----------------
app.get('/api/projects', requireAuth, async (req, res) => {
    const projects = await Project.findAll({ include: [{ model: User, as: 'manager', attributes: ['id','name','email'] }] });
    res.json(projects);
});

app.get('/api/projects/:id', requireAuth, async (req, res) => {
    const project = await Project.findByPk(req.params.id, {
        include: [
            { model: User, as: 'manager', attributes: ['id','name','email'] },
            { model: Task, include: [{ model: User, as: 'assignedUser', attributes: ['id','name','email'] }] }
        ]
    });
    if (!project) return res.status(404).json({ error: 'Project not found' });
    res.json(project);
});

app.post('/api/projects', requireAuth, async (req, res) => {
    const { name, description, status = 'active' } = req.body;
    const newProject = await Project.create({ name, description, status, managerId: req.user.id });
    res.status(201).json(newProject);
});

app.put('/api/projects/:id', requireAuth, async (req, res) => {
    const { name, description, status } = req.body;
    const [updatedRows] = await Project.update({ name, description, status }, { where: { id: req.params.id } });
    if (!updatedRows) return res.status(404).json({ error: 'Project not found' });
    const updatedProject = await Project.findByPk(req.params.id);
    res.json(updatedProject);
});

app.delete('/api/projects/:id', requireAuth, async (req, res) => {
    const deletedRows = await Project.destroy({ where: { id: req.params.id } });
    if (!deletedRows) return res.status(404).json({ error: 'Project not found' });
    res.json({ message: 'Project deleted successfully' });
});

// ----------------- TASK ROUTES -----------------
app.get('/api/projects/:id/tasks', requireAuth, async (req, res) => {
    const tasks = await Task.findAll({ where: { projectId: req.params.id }, include: [{ model: User, as: 'assignedUser', attributes: ['id','name','email'] }] });
    res.json(tasks);
});

app.post('/api/projects/:id/tasks', requireAuth, async (req, res) => {
    const { title, description, assignedUserId, priority = 'medium' } = req.body;
    const newTask = await Task.create({ title, description, projectId: req.params.id, assignedUserId, priority, status: 'pending' });
    res.status(201).json(newTask);
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
    const { title, description, status, priority } = req.body;
    const [updatedRows] = await Task.update({ title, description, status, priority }, { where: { id: req.params.id } });
    if (!updatedRows) return res.status(404).json({ error: 'Task not found' });
    const updatedTask = await Task.findByPk(req.params.id);
    res.json(updatedTask);
});

app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
    const deletedRows = await Task.destroy({ where: { id: req.params.id } });
    if (!deletedRows) return res.status(404).json({ error: 'Task not found' });
    res.json({ message: 'Task deleted successfully' });
});

// ----------------- START SERVER -----------------
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
});