const { setServers } = require("node:dns/promises");
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const app = express();
require("dotenv").config();
const jwt = require("jsonwebtoken");
const { z } = require("zod");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const port = process.env.PORT || 5000;

setServers(["1.1.1.1", "8.8.8.8"]);

app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:3000", "https://zyplo-six.vercel.app"],
    credentials: true,
  }),
);

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.u1z8wkz.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.NEXTAUTH_SECRET);

    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

// Zod Schema -> Invite Member (Rifat)
const inviteSchema = z.object({
  email: z.email(),
  role: z.enum(["admin", "member"]),
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();

    const db = client.db("zyplo-db");
    const usersCollection = db.collection("users");
    //added for workspace
    const workspacesCollection = db.collection("workspaces");
    const projectsCollection = db.collection("projects");
    const boardsCollection = db.collection("boards");
    const tasksCollection = db.collection("tasks");
    const notificationsCollection = db.collection("notifications");
    const inviteCollection = db.collection("invites");

    // register api
    const bcrypt = require("bcryptjs");

    // New variables
    const toId = (v) => new ObjectId(String(v));
    const now = () => new Date().toISOString();
    const normalizeEmail = (value) =>
      String(value || "")
        .trim()
        .toLowerCase();

    // Basic Gmail SMTP sender using .env credentials.
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.USER_EMAIL,
        pass: process.env.USER_PASS,
      },
    });

    const sendInviteEmail = async ({ to, subject, html }) => {
      if (!process.env.USER_EMAIL || !process.env.USER_PASS) {
        throw new Error("Missing USER_EMAIL or USER_PASS");
      }

      return transporter.sendMail({
        from: process.env.USER_EMAIL,
        to,
        subject,
        html,
      });
    };

    const getUserIdentity = (req) => ({
      id: req.user?.id || req.headers["x-user-id"],
      email: req.user?.email || req.headers["x-user-email"] || "",
      name: req.user?.name || req.headers["x-user-name"] || "User",
    });

    const isWorkspaceMember = (workspace, me) => {
      const myId = String(me?.id || "");
      const myEmail = normalizeEmail(me?.email);
      return (workspace?.members || []).some(
        (m) =>
          (myId && String(m.userId || "") === myId) ||
          (myEmail && normalizeEmail(m.email) === myEmail),
      );
    };
    const isWorkspaceAdmin = (workspace, me) => {
      const myId = String(me?.id || "");
      const myEmail = normalizeEmail(me?.email);
      return (workspace?.members || []).some((m) => {
        const role = String(m.role || "").toLowerCase();
        const byId = myId && String(m.userId || "") === myId;
        const byEmail = myEmail && normalizeEmail(m.email) === myEmail;
        return (byId || byEmail) && role === "admin";
      });
    };

    const isValidId = (v) => ObjectId.isValid(String(v || ""));
    const statusFromColumnName = (name) =>
      String(name || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "_")
        .replace(/^_+|_+$/g, "");

    app.post("/auth/register", async (req, res) => {
      try {
        const { name, email, password, role } = req.body;

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await usersCollection.insertOne({
          name,
          email,
          password: hashedPassword,
          role,
          provider: "credentials",
          loginAttempts: 0,
          lockUntil: null,
          createdAt: new Date().toISOString(),
        });

        res.json({ message: "User registered successfully" });
      } catch (err) {
        res.status(500).json({ message: "Registration failed" });
      }
    });

    app.post("/auth/oauth", async (req, res) => {
      try {
        const { name, email, provider, providerId, image, role } = req.body;

        let user = await usersCollection.findOne({ email });

        if (!user) {
          const result = await usersCollection.insertOne({
            name,
            email,
            image,
            role,
            provider,
            providerId,
            createdAt: new Date().toISOString(),
          });

          user = {
            _id: result.insertedId,
            name,
            email,
          };
        }

        res.json({
          id: user._id,
          name: user.name,
          email: user.email,
        });
      } catch (err) {
        res.status(500).json({ message: "OAuth failed" });
      }
    });

    // login api
    const jwt = require("jsonwebtoken"); //DUPLICATE REQUIRE

    const MAX_LOGIN_ATTEMPTS = 5;
    const LOCK_TIME = 30 * 1000;

    app.post("/auth/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(400).json({ message: "Invalid credentials" });
        }

        if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
          return res.status(403).json({
            message: "Account locked",
            lockUntil: user.lockUntil,
          });
        }

        const isValid = await bcrypt.compare(password, user.password);

        if (!isValid) {
          const attempts = (user.loginAttempts || 0) + 1;

          const updateData = {
            loginAttempts: attempts,
          };

          if (attempts >= MAX_LOGIN_ATTEMPTS) {
            updateData.lockUntil = new Date(
              Date.now() + LOCK_TIME,
            ).toISOString();
          }

          await usersCollection.updateOne(
            { _id: user._id },
            { $set: updateData },
          );

          return res.status(400).json({
            message: "Invalid credentials",
          });
        }

        await usersCollection.updateOne(
          { _id: user._id },
          {
            $set: {
              loginAttempts: 0,
              lockUntil: null,
            },
          },
        );

        res.json({
          id: user._id,
          name: user.name,
          email: user.email,
        });
      } catch (err) {
        res.status(500).json({ message: "Login failed" });
      }
    });

    // users api

    app.get("/users", async (req, res) => {});

    app.post("/users", async (req, res) => {
      const users = req.body;
      const result = await usersCollection.insertOne(users);
      res.send(result);
    });

    // GET /dashboard/bootstrap
    app.get("/dashboard/bootstrap", verifyToken, async (req, res) => {
      const me = getUserIdentity(req);
      console.log(me);
      if (!me.id) return res.status(401).json({ error: "Unauthorized" });

      const workspaceDocs = await workspacesCollection
        .find({ "members.userId": String(me.id) })
        .sort({ createdAt: -1 })
        .toArray();

      const workspaceIds = workspaceDocs.map((w) => w._id);
      const projects = await projectsCollection
        .find({ workspaceId: { $in: workspaceIds } })
        .toArray();
      const tasks = await tasksCollection
        .find({ workspaceId: { $in: workspaceIds } })
        .sort({ createdAt: -1 })
        .toArray();
      const notifications = await notificationsCollection
        .find({ userId: String(me.id) })
        .sort({ createdAt: -1 })
        .limit(50)
        .toArray();

      const workspaces = workspaceDocs.map((w) => ({
        id: String(w._id),
        name: w.name,
        slug: w.slug,
        members: w.members || [],
      }));

      res.json({
        currentUser: { id: String(me.id), name: me.name, email: me.email },
        workspaces,
        projects: projects.map((p) => ({
          id: String(p._id),
          workspaceId: String(p.workspaceId),
          name: p.name,
          key: p.key,
          status: p.status || "active",
          createdAt: p.createdAt,
        })),
        tasks: tasks.map((t) => ({
          id: String(t._id),
          workspaceId: String(t.workspaceId),
          projectId: t.projectId ? String(t.projectId) : "",
          boardId: t.boardId ? String(t.boardId) : "",
          columnId: t.columnId ? String(t.columnId) : "",
          order: Number.isInteger(t.order) ? t.order : 0,
          projectName: t.projectName || "",
          title: t.title,
          description: t.description || "",
          priority: t.priority || "P2",
          status: t.status || "todo",
          dueDate: t.dueDate || "",
          assigneeId: t.assigneeId || "",
          assigneeName: t.assigneeName || "Unassigned",
          createdAt: t.createdAt,
        })),
        activity: [],
        notifications: notifications.map((n) => ({
          id: String(n._id),
          text: n.text,
          read: !!n.read,
          createdAt: n.createdAt,
        })),
        lastVisited: null,
      });
    });

    // POST /dashboard/workspaces
    app.post("/dashboard/workspaces", verifyToken, async (req, res) => {
      const me = getUserIdentity(req);
      const { name, memberEmails = [] } = req.body || {};
      if (!name?.trim())
        return res.status(400).json({ error: "Workspace name is required" });

      const members = [
        {
          id: String(me.id),
          userId: String(me.id),
          name: me.name,
          email: me.email,
          role: "admin", //changed to admin
        },
      ];

      for (const raw of memberEmails) {
        const email = normalizeEmail(raw);
        if (!email || members.some((m) => normalizeEmail(m.email) === email))
          continue;
        members.push({
          id: new ObjectId().toString(),
          userId: "",
          name: email.split("@")[0],
          email,
          role: "Member",
        });
      }

      const doc = {
        name: name.trim(),
        slug: name
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/(^-|-$)/g, ""),
        members,
        createdBy: String(me.id),
        createdAt: now(),
      };

      const result = await workspacesCollection.insertOne(doc);
      res.status(201).json({
        workspace: {
          id: String(result.insertedId),
          name: doc.name,
          slug: doc.slug,
          members: doc.members,
        },
      });
    });

    // POST /dashboard/workspaces/:workspaceId/members
    app.post(
      "/dashboard/workspaces/:workspaceId/members",
      verifyToken,
      async (req, res) => {
        const { workspaceId } = req.params;
        const { email, role = "Member" } = req.body || {};
        const clean = normalizeEmail(email);
        if (!clean)
          return res.status(400).json({ error: "Member email is required" });

        const workspace = await workspacesCollection.findOne({
          _id: toId(workspaceId),
        });
        if (!workspace)
          return res.status(404).json({ error: "Workspace not found" });

        const exists = (workspace.members || []).find(
          (m) => normalizeEmail(m.email) === clean,
        );
        if (exists) return res.status(201).json({ member: exists });

        const member = {
          id: new ObjectId().toString(),
          userId: "",
          name: clean.split("@")[0],
          email: clean,
          role,
        };

        await workspacesCollection.updateOne(
          { _id: toId(workspaceId) },
          { $push: { members: member } },
        );

        res.status(201).json({ member });
      },
    );

    app.delete(
      "/dashboard/workspaces/:workspaceId",
      verifyToken,
      async (req, res) => {
        const { workspaceId } = req.params;
        const me = getUserIdentity(req);

        const workspace = await workspacesCollection.findOne({
          _id: toId(workspaceId),
        });
        if (!workspace)
          return res.status(404).json({ error: "Workspace not found" });

        const isAdmin = (workspace.members || []).some(
          (m) => String(m.userId) === String(me.id) && m.role === "admin",
        );
        if (!isAdmin)
          return res
            .status(403)
            .json({ error: "Only admin can delete workspace" });

        await projectsCollection.deleteMany({ workspaceId: toId(workspaceId) });
        await boardsCollection.deleteMany({ workspaceId: toId(workspaceId) });
        await tasksCollection.deleteMany({ workspaceId: toId(workspaceId) });
        await workspacesCollection.deleteOne({ _id: toId(workspaceId) });

        return res.json({ ok: true });
      },
    );

    // POST /dashboard/projects
    app.post("/dashboard/projects", verifyToken, async (req, res) => {
      const { workspaceId, name, key = "" } = req.body || {};
      if (!workspaceId || !name?.trim())
        return res
          .status(400)
          .json({ error: "workspaceId and project name are required" });
      if (!isValidId(workspaceId))
        return res.status(400).json({ error: "Invalid workspaceId" });

      const workspace = await workspacesCollection.findOne({
        _id: toId(workspaceId),
      });
      if (!workspace)
        return res.status(404).json({ error: "Workspace not found" });

      const me = getUserIdentity(req);
      if (!isWorkspaceMember(workspace, me))
        return res.status(403).json({ error: "Forbidden workspace access" });

      const project = {
        workspaceId: toId(workspaceId),
        name: name.trim(),
        key:
          String(key || name)
            .toUpperCase()
            .replace(/[^A-Z0-9]+/g, "")
            .slice(0, 6) || "PROJ",
        status: "active",
        createdAt: now(),
      };

      const defaultColumns = [
        { _id: new ObjectId(), name: "To Do", order: 0 },
        { _id: new ObjectId(), name: "In Progress", order: 1 },
        { _id: new ObjectId(), name: "In Review", order: 2 },
        { _id: new ObjectId(), name: "Done", order: 3 },
      ];

      const session = client.startSession();
      let createdProjectId = null;
      let createdBoardId = null;

      try {
        await session.withTransaction(async () => {
          const projectResult = await projectsCollection.insertOne(project, {
            session,
          });
          createdProjectId = projectResult.insertedId;

          const boardDoc = {
            workspaceId: toId(workspaceId),
            projectId: createdProjectId,
            name: "Default Board",
            columns: defaultColumns,
            createdAt: now(),
          };

          const boardResult = await boardsCollection.insertOne(boardDoc, {
            session,
          });
          createdBoardId = boardResult.insertedId;
        });
      } finally {
        await session.endSession();
      }

      res.status(201).json({
        project: {
          id: String(createdProjectId),
          workspaceId: String(project.workspaceId),
          name: project.name,
          key: project.key,
          status: project.status,
          createdAt: project.createdAt,
        },
        board: {
          id: String(createdBoardId),
          name: "Default Board",
          columns: defaultColumns.map((c) => ({
            id: String(c._id),
            name: c.name,
            order: c.order,
          })),
        },
      });
    });

    // POST /dashboard/tasks
    app.post("/dashboard/tasks", verifyToken, async (req, res) => {
      const {
        workspaceId,
        projectId = "",
        boardId = "",
        columnId = "",
        title,
        description = "",
        priority = "P2",
        status = "todo",
        dueDate = "",
        assigneeId = "",
      } = req.body || {};
      if (!workspaceId || !projectId || !boardId || !columnId || !title?.trim())
        return res.status(400).json({
          error:
            "workspaceId, projectId, boardId, columnId and title are required",
        });
      if (
        !isValidId(workspaceId) ||
        !isValidId(projectId) ||
        !isValidId(boardId) ||
        !isValidId(columnId)
      ) {
        return res.status(400).json({
          error: "workspaceId, projectId, boardId or columnId is invalid",
        });
      }

      const workspace = await workspacesCollection.findOne({
        _id: toId(workspaceId),
      });
      if (!workspace)
        return res.status(404).json({ error: "Workspace not found" });

      const me = getUserIdentity(req);
      if (!isWorkspaceMember(workspace, me))
        return res.status(403).json({ error: "Forbidden workspace access" });

      const project = await projectsCollection.findOne({
        _id: toId(projectId),
        workspaceId: toId(workspaceId),
      });
      if (!project)
        return res
          .status(404)
          .json({ error: "Project not found in this workspace" });

      const board = await boardsCollection.findOne({
        _id: toId(boardId),
        workspaceId: toId(workspaceId),
        projectId: toId(projectId),
      });
      if (!board) return res.status(404).json({ error: "Board not found" });

      const hasColumn = (board.columns || []).some(
        (c) => String(c._id) === String(toId(columnId)),
      );
      if (!hasColumn)
        return res.status(400).json({ error: "Invalid columnId for board" });

      const assignee =
        (workspace.members || []).find((m) => m.id === assigneeId) ||
        (workspace.members || [])[0] ||
        null;

      const lastTask = await tasksCollection
        .find({
          workspaceId: toId(workspaceId),
          projectId: toId(projectId),
          boardId: toId(boardId),
          columnId: toId(columnId),
        })
        .sort({ order: -1 })
        .limit(1)
        .toArray();
      const nextOrder =
        lastTask.length > 0 && Number.isInteger(lastTask[0].order)
          ? lastTask[0].order + 1
          : 0;

      const task = {
        workspaceId: toId(workspaceId),
        projectId: toId(projectId),
        boardId: toId(boardId),
        columnId: toId(columnId),
        order: nextOrder,
        projectName: project.name,
        title: title.trim(),
        description,
        priority,
        status,
        dueDate,
        assigneeId: assignee?.id || "",
        assigneeName: assignee?.name || "Unassigned",
        createdAt: now(),
      };

      const result = await tasksCollection.insertOne(task);
      res.status(201).json({
        task: {
          id: String(result.insertedId),
          workspaceId,
          projectId: String(task.projectId),
          boardId: String(task.boardId),
          columnId: String(task.columnId),
          order: task.order,
          projectName: task.projectName,
          title: task.title,
          description: task.description,
          priority: task.priority,
          status: task.status,
          dueDate: task.dueDate,
          assigneeId: task.assigneeId,
          assigneeName: task.assigneeName,
          createdAt: task.createdAt,
        },
      });
    });

    // new api for board
    app.get("/dashboard/boards/:projectId", verifyToken, async (req, res) => {
      const { projectId } = req.params;
      const me = getUserIdentity(req);
      if (!isValidId(projectId))
        return res.status(400).json({ error: "Invalid projectId" });

      const project = await projectsCollection.findOne({
        _id: toId(projectId),
      });
      if (!project) return res.status(404).json({ error: "Project not found" });

      const workspace = await workspacesCollection.findOne({
        _id: toId(project.workspaceId),
      });
      if (!workspace)
        return res.status(404).json({ error: "Workspace not found" });
      if (!isWorkspaceMember(workspace, me))
        return res.status(403).json({ error: "Forbidden workspace access" });

      const board = await boardsCollection.findOne({
        projectId: toId(projectId),
        workspaceId: toId(project.workspaceId),
      });
      if (!board) return res.status(404).json({ error: "Board not found" });

      const sortedColumns = [...(board.columns || [])].sort(
        (a, b) => Number(a.order || 0) - Number(b.order || 0),
      );
      const tasks = await tasksCollection
        .find({ boardId: toId(board._id), projectId: toId(projectId) })
        .sort({ order: 1, createdAt: 1 })
        .toArray();

      const columns = sortedColumns.map((col) => ({
        id: String(col._id),
        name: col.name,
        order: Number(col.order || 0),
        tasks: tasks
          .filter((t) => String(t.columnId) === String(col._id))
          .sort((a, b) => Number(a.order || 0) - Number(b.order || 0))
          .map((t) => ({
            id: String(t._id),
            workspaceId: String(t.workspaceId),
            projectId: t.projectId ? String(t.projectId) : "",
            boardId: t.boardId ? String(t.boardId) : "",
            columnId: t.columnId ? String(t.columnId) : "",
            order: Number(t.order || 0),
            projectName: t.projectName || "",
            title: t.title,
            description: t.description || "",
            priority: t.priority || "P2",
            status: t.status || "todo",
            dueDate: t.dueDate || "",
            assigneeId: t.assigneeId || "",
            assigneeName: t.assigneeName || "Unassigned",
            createdAt: t.createdAt,
          })),
      }));

      return res.json({
        board: {
          id: String(board._id),
          workspaceId: String(board.workspaceId),
          projectId: String(board.projectId),
          name: board.name,
          createdAt: board.createdAt,
        },
        columns,
      });
    });

    app.patch(
      "/dashboard/tasks/:taskId/move",
      verifyToken,
      async (req, res) => {
        const { taskId } = req.params;
        const {
          sourceColumnId,
          destinationColumnId,
          destinationBoardId = "",
          newOrder,
          status,
        } = req.body || {};

        if (
          !taskId ||
          !sourceColumnId ||
          !destinationColumnId ||
          !Number.isInteger(newOrder) ||
          newOrder < 0
        ) {
          return res.status(400).json({
            error:
              "taskId, sourceColumnId, destinationColumnId and non-negative integer newOrder are required",
          });
        }
        if (
          !isValidId(taskId) ||
          !isValidId(sourceColumnId) ||
          !isValidId(destinationColumnId)
        ) {
          return res.status(400).json({
            error: "taskId, sourceColumnId or destinationColumnId is invalid",
          });
        }
        if (destinationBoardId && !isValidId(destinationBoardId)) {
          return res.status(400).json({
            error: "destinationBoardId is invalid",
          });
        }

        const me = getUserIdentity(req);
        const session = client.startSession();

        try {
          let responsePayload = null;

          await session.withTransaction(async () => {
            const task = await tasksCollection.findOne(
              { _id: toId(taskId) },
              { session },
            );
            if (!task) throw { status: 404, message: "Task not found" };
            if (!task.workspaceId || !task.projectId || !task.boardId) {
              throw { status: 400, message: "Task is not linked to a board" };
            }

            if (String(task.columnId) !== String(toId(sourceColumnId))) {
              throw {
                status: 400,
                message: "sourceColumnId does not match current task columnId",
              };
            }

            const workspace = await workspacesCollection.findOne(
              { _id: toId(task.workspaceId) },
              { session },
            );
            if (!workspace)
              throw { status: 404, message: "Workspace not found" };
            if (!isWorkspaceMember(workspace, me)) {
              throw { status: 403, message: "Forbidden workspace access" };
            }

            const project = await projectsCollection.findOne(
              {
                _id: toId(task.projectId),
                workspaceId: toId(task.workspaceId),
              },
              { session },
            );
            if (!project)
              throw { status: 404, message: "Project not found in workspace" };

            const sourceBoard = await boardsCollection.findOne(
              {
                _id: toId(task.boardId),
                workspaceId: toId(task.workspaceId),
                projectId: toId(task.projectId),
              },
              { session },
            );
            const sourceId = toId(sourceColumnId);
            if (!sourceBoard) throw { status: 404, message: "Board not found" };

            const sourceBoardColumnIds = new Set(
              (sourceBoard.columns || []).map((c) => String(c._id)),
            );
            if (!sourceBoardColumnIds.has(String(sourceId))) {
              throw { status: 400, message: "Invalid source column for board" };
            }

            const targetBoardId = destinationBoardId
              ? toId(destinationBoardId)
              : toId(task.boardId);
            const destinationBoard =
              String(targetBoardId) === String(sourceBoard._id)
                ? sourceBoard
                : await boardsCollection.findOne(
                    {
                      _id: targetBoardId,
                      workspaceId: toId(task.workspaceId),
                      projectId: toId(task.projectId),
                    },
                    { session },
                  );
            if (!destinationBoard) {
              throw { status: 404, message: "Destination board not found" };
            }

            const destinationId = toId(destinationColumnId);
            const destinationBoardColumnIds = new Set(
              (destinationBoard.columns || []).map((c) => String(c._id)),
            );
            if (!destinationBoardColumnIds.has(String(destinationId))) {
              throw {
                status: 400,
                message: "Invalid destination column for destination board",
              };
            }

            const destinationColumn = (destinationBoard.columns || []).find(
              (c) => String(c._id) === String(destinationId),
            );
            const explicitStatus =
              typeof status === "string" ? status.trim() : "";
            const nextStatus =
              explicitStatus ||
              statusFromColumnName(destinationColumn?.name) ||
              task.status ||
              "todo";

            const sameBoard = String(sourceBoard._id) === String(targetBoardId);
            const sameColumn =
              sameBoard && String(sourceId) === String(destinationId);

            const sourceTasksWithoutMoved = await tasksCollection
              .find(
                {
                  boardId: toId(sourceBoard._id),
                  columnId: sourceId,
                  _id: { $ne: toId(taskId) },
                },
                { session },
              )
              .sort({ order: 1, createdAt: 1 })
              .toArray();

            const ops = [];

            if (sameColumn) {
              const insertAt = Math.min(
                newOrder,
                sourceTasksWithoutMoved.length,
              );
              const reordered = [...sourceTasksWithoutMoved];
              reordered.splice(insertAt, 0, task);

              reordered.forEach((t, index) => {
                const $set = { order: index };
                if (String(t._id) === String(task._id) && explicitStatus) {
                  $set.status = nextStatus;
                }
                ops.push({
                  updateOne: {
                    filter: { _id: toId(t._id) },
                    update: { $set },
                  },
                });
              });
            } else {
              const destinationTasks = await tasksCollection
                .find(
                  { boardId: targetBoardId, columnId: destinationId },
                  { session },
                )
                .sort({ order: 1, createdAt: 1 })
                .toArray();

              sourceTasksWithoutMoved.forEach((t, index) => {
                ops.push({
                  updateOne: {
                    filter: { _id: toId(t._id) },
                    update: { $set: { order: index } },
                  },
                });
              });

              const insertAt = Math.min(newOrder, destinationTasks.length);
              const destinationReordered = [...destinationTasks];
              destinationReordered.splice(insertAt, 0, {
                ...task,
                boardId: targetBoardId,
                columnId: destinationId,
                status: nextStatus,
              });

              destinationReordered.forEach((t, index) => {
                if (String(t._id) === String(task._id)) {
                  ops.push({
                    updateOne: {
                      filter: { _id: toId(task._id) },
                      update: {
                        $set: {
                          boardId: targetBoardId,
                          columnId: destinationId,
                          order: index,
                          status: nextStatus,
                        },
                      },
                    },
                  });
                } else {
                  ops.push({
                    updateOne: {
                      filter: { _id: toId(t._id) },
                      update: { $set: { order: index } },
                    },
                  });
                }
              });
            }

            if (ops.length > 0) {
              await tasksCollection.bulkWrite(ops, { session });
            }

            const responseBoard = destinationBoard;
            const sortedColumns = [...(responseBoard.columns || [])].sort(
              (a, b) => Number(a.order || 0) - Number(b.order || 0),
            );
            const boardTasks = await tasksCollection
              .find(
                {
                  boardId: toId(responseBoard._id),
                  workspaceId: toId(task.workspaceId),
                  projectId: toId(task.projectId),
                },
                { session },
              )
              .sort({ order: 1, createdAt: 1 })
              .toArray();

            responsePayload = {
              boardId: String(responseBoard._id),
              projectId: String(project._id),
              workspaceId: String(workspace._id),
              columns: sortedColumns.map((col) => ({
                id: String(col._id),
                name: col.name,
                order: Number(col.order || 0),
                tasks: boardTasks
                  .filter((t) => String(t.columnId) === String(col._id))
                  .sort((a, b) => Number(a.order || 0) - Number(b.order || 0))
                  .map((t) => ({
                    id: String(t._id),
                    workspaceId: String(t.workspaceId),
                    projectId: t.projectId ? String(t.projectId) : "",
                    boardId: t.boardId ? String(t.boardId) : "",
                    columnId: t.columnId ? String(t.columnId) : "",
                    order: Number(t.order || 0),
                    projectName: t.projectName || "",
                    title: t.title,
                    description: t.description || "",
                    priority: t.priority || "P2",
                    status: t.status || "todo",
                    dueDate: t.dueDate || "",
                    assigneeId: t.assigneeId || "",
                    assigneeName: t.assigneeName || "Unassigned",
                    createdAt: t.createdAt,
                  })),
              })),
            };
          });

          return res.json(responsePayload);
        } catch (error) {
          if (error?.status && error?.message) {
            return res.status(error.status).json({ error: error.message });
          }
          console.error(error);
          return res.status(500).json({ error: "Failed to move task" });
        } finally {
          await session.endSession();
        }
      },
    );

    // PATCH /dashboard/tasks/:taskId
    app.patch("/dashboard/tasks/:taskId", verifyToken, async (req, res) => {
      const { taskId } = req.params;
      const patch = req.body || {};
      const me = getUserIdentity(req);
      if (!isValidId(taskId))
        return res.status(400).json({ error: "Invalid taskId" });

      const existingTask = await tasksCollection.findOne({ _id: toId(taskId) });
      if (!existingTask)
        return res.status(404).json({ error: "Task not found" });

      const workspace = await workspacesCollection.findOne({
        _id: toId(existingTask.workspaceId),
      });
      if (!workspace)
        return res.status(404).json({ error: "Workspace not found" });
      if (!isWorkspaceMember(workspace, me))
        return res.status(403).json({ error: "Forbidden workspace access" });

      const $set = {};
      for (const k of [
        "title",
        "description",
        "priority",
        "status",
        "dueDate",
        "assigneeId",
        "assigneeName",
        "projectName",
      ]) {
        if (typeof patch[k] === "string") $set[k] = patch[k];
      }
      if (patch.projectId !== undefined) {
        if (!patch.projectId) {
          $set.projectId = null;
        } else {
          if (!isValidId(patch.projectId))
            return res.status(400).json({ error: "Invalid projectId" });
          const nextProject = await projectsCollection.findOne({
            _id: toId(patch.projectId),
            workspaceId: toId(existingTask.workspaceId),
          });
          if (!nextProject)
            return res
              .status(404)
              .json({ error: "Project not found in this workspace" });
          $set.projectId = toId(patch.projectId);
        }
      }

      const result = await tasksCollection.findOneAndUpdate(
        { _id: toId(taskId) },
        { $set },
        { returnDocument: "after" },
      );

      if (!result.value)
        return res.status(404).json({ error: "Task not found" });

      const t = result.value;
      res.json({
        task: {
          id: String(t._id),
          workspaceId: String(t.workspaceId),
          projectId: t.projectId ? String(t.projectId) : "",
          boardId: t.boardId ? String(t.boardId) : "",
          columnId: t.columnId ? String(t.columnId) : "",
          order: Number.isInteger(t.order) ? t.order : 0,
          projectName: t.projectName || "",
          title: t.title,
          description: t.description || "",
          priority: t.priority || "P2",
          status: t.status || "todo",
          dueDate: t.dueDate || "",
          assigneeId: t.assigneeId || "",
          assigneeName: t.assigneeName || "Unassigned",
          createdAt: t.createdAt,
        },
      });
    });

    // POST /dashboard/notifications/read-all
    app.post(
      "/dashboard/notifications/read-all",
      verifyToken,
      async (req, res) => {
        const me = getUserIdentity(req);
        await notificationsCollection.updateMany(
          { userId: String(me.id), read: false },
          { $set: { read: true } },
        );
        res.json({ ok: true });
      },
    );

    // Invite Feature--------->Rifat_START

    // get all invites for a workspace.
    app.get("/workspaces/:workspaceId/invites", verifyToken, async (req, res) => {
      try {
        const { workspaceId } = req.params;
        const me = getUserIdentity(req);

        // isValidId--> checks valid workspaceId
        if (!isValidId(workspaceId)) {
          return res
            .status(400)
            .json({ ok: false, message: "Invalid workspace id" });
        }

        // find the workspace
        // toId--> converts to ObjectId
        const workspace = await workspacesCollection.findOne({
          _id: toId(workspaceId),
        });
        if (!workspace) {
          return res
            .status(404)
            .json({ ok: false, message: "Workspace not found" });
        }
        if (!isWorkspaceMember(workspace, me)) {
          return res.status(403).json({ ok: false, message: "Forbidden" });
        }

        // finds all invites under a workspace
        const invites = await inviteCollection
          .find({ workspaceId })
          .sort({ createdAt: -1 })
          .toArray();

        // UI-friendly response: include workspace.members with id/name/email/role.
        return res.json({
          ok: true,
          workspace: {
            id: String(workspace._id),
            name: workspace.name,
            // workspace members are in a arr
            members: (workspace.members || []).map((member) => ({
              id: member.id || member.userId || new ObjectId().toString(),
              name:
                member.name ||
                (member.email ? member.email.split("@")[0] : "Member"),
              email: member.email || "",
              role: member.role || "Member",
            })),
          },
          invites,
        });
      } catch (error) {
        console.error(error);
        return res.status(500).json({ ok: false, message: "Server error" });
      }
    });

    // post invites
    app.post("/workspaces/:workspaceId/invites", verifyToken, async (req, res) => {
      try {
        const clientSideData = inviteSchema.parse(req.body);
        const role = clientSideData.role;
        const email = normalizeEmail(clientSideData.email);
        const { workspaceId } = req.params;
        const me = getUserIdentity(req);

        // Checks valid workspace
        if (!isValidId(workspaceId)) {
          return res
            .status(400)
            .json({ ok: false, message: "Invalid workspace id" });
        }
        // find the workspace
        const workspace = await workspacesCollection.findOne({
          _id: toId(workspaceId),
        });

        if (!workspace) {
          return res
            .status(404)
            .json({ ok: false, message: "Workspace not found" });
        }
        if (!isWorkspaceAdmin(workspace, me)) {
          return res.status(403).json({ ok: false, message: "Forbidden" });
        }
        // generate random token for URL and hashed version for DB
        const rawToken = crypto.randomBytes(32).toString("hex");
        const hashedToken = crypto
          .createHash("sha256")
          .update(rawToken)
          .digest("hex");

        // Create a Link to send via Email/Console
        const frontendURL = process.env.FRONTEND_URL || "http://localhost:3000";
        const inviteLink = `${frontendURL}/accept-invite/${rawToken}`;

        // find if the user is already a member
        const existingMember = isWorkspaceMember(workspace, { id: "", email });

        // do this if found in existing workspace
        if (existingMember) {
          return res.status(409).json({
            ok: false,
            message: "User is already in workspace",
          });
        }

        // find if the user is already invited
        const existingInvite = await inviteCollection.findOne({
          email,
          workspaceId,
          status: "pending",
          expiresAt: { $gt: new Date() },
        });

        // do this if found in existing db
        if (existingInvite) {
          return res.status(409).json({
            ok: false,
            message: "Invite already sent",
            expiresAt: existingInvite.expiresAt,
          });
        }

        //  invite data for db
        const inviteData = {
          email,
          role,
          workspaceId,
          workspaceName: workspace.name,
          status: "pending",
          token: hashedToken,
          createdAt: new Date(),
          expiresAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
        };

        // send invite data to db
        const result = await inviteCollection.insertOne(inviteData);

        // After invite data is stored, send invite email via Gmail SMTP.
        try {
          await sendInviteEmail({
            to: email,
            subject: `You're invited to join ${workspace.name}`,
            html: `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        /* Responsive styles for mobile clients */
        @media only screen and (max-width: 600px) {
          .container { width: 100% !important; border-radius: 0 !important; border: none !important; }
          .content { padding: 30px 20px !important; }
          .button { width: 100% !important; text-align: center; display: block !important; box-sizing: border-box; }
        }
      </style>
    </head>
    <body style="margin:0;padding:0;background-color:#f4f7fa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
      <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color:#f4f7fa;padding:40px 0;">
        <tr>
          <td align="center">
            <table class="container" width="560" border="0" cellspacing="0" cellpadding="0" style="background-color:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 10px 15px -3px rgba(0,0,0,0.1);border:1px solid #e5e7eb;">
              
              <tr>
                <td class="content" style="padding:40px 40px 0 40px;">
                  <img src="https://res.cloudinary.com/dsyahfiyo/image/upload/v1772881604/logo1_b7iv2u.png" 
                       alt="${workspace.name}" 
                       width="48" 
                       style="display:block; border:0; outline:none; text-decoration:none; max-width:120px; height:auto;">
                </td>
              </tr>

              <tr>
                <td class="content" style="padding:32px 40px 40px 40px;">
                  <h1 style="margin:0 0 16px;font-size:24px;font-weight:700;color:#111827;line-height:1.2;">
                    Join the workspace
                  </h1>
                  <p style="margin:0 0 20px;font-size:16px;line-height:1.6;color:#4b5563;">
                    Hi there! You've been invited to join <strong>${workspace.name}</strong> as a 
                    <span style="background:#f3f4f6;color:#111827;padding:2px 8px;border-radius:4px;font-weight:600;font-size:14px;text-transform:capitalize;">${role}</span>.
                  </p>
                  <p style="margin:0 0 32px;font-size:16px;line-height:1.6;color:#4b5563;">
                    Collaborate with your team, manage projects, and stay updated—all in one place.
                  </p>
                  
                  <a href="${inviteLink}" class="button" style="display:inline-block;background-color:#4f46e5;color:#ffffff;text-decoration:none;font-size:16px;font-weight:600;padding:14px 30px;border-radius:8px;">
                    Accept Invitation
                  </a>
                </td>
              </tr>

              <tr>
                <td style="padding:30px 40px;background-color:#f9fafb;border-top:1px solid #e5e7eb;">
                  <p style="margin:0 0 10px;font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;font-weight:700;">
                    Trouble with the button?
                  </p>
                  <p style="margin:0;font-size:13px;line-height:1.5;word-break:break-all;">
                    <a href="${inviteLink}" style="color:#4f46e5;text-decoration:none;">${inviteLink}</a>
                  </p>
                </td>
              </tr>
            </table>

            <table width="560" class="container" border="0" cellspacing="0" cellpadding="0">
              <tr>
                <td style="padding:24px 10px;text-align:center;">
                  <p style="margin:0;font-size:12px;color:#9ca3af;line-height:1.4;">
                    This invitation was sent to you by ${workspace.name}.<br>
                    If you weren't expecting this, you can safely ignore this email.
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
  `,
          });
        } catch (mailError) {
          // Keep invite creation successful even if email sending fails.
          console.error("SMTP send failed:", mailError?.message || mailError);
        }

        // send response to frontend
        return res.status(201).json({
          ok: true,
          inviteLink,
          message: "Invite created!",
          workspaceName: workspace.name,
          status: inviteData.status,
          expiresAt: inviteData.expiresAt,
        });
      } catch (error) {
        // catch zod error
        if (error instanceof z.ZodError) {
          return res.status(400).json({
            ok: false,
            message: "Validation failed",
            errors: error,
          });
        }
        // catch and send other error
        console.error(error);
        return res.status(500).json({ ok: false, message: "Server error" });
      }
    });

    // check valid invitation
    app.get("/invites/:token", async (req, res) => {
      try {
        const { token } = req.params;

        const hashedToken = crypto
          .createHash("sha256")
          .update(token)
          .digest("hex");

        // check token existence in db
        const findInvite = await inviteCollection.findOne({
          token: hashedToken,
        });

        // if not found --> Invalid token
        if (!findInvite)
          return res.status(404).json({ message: "Invalid Token", ok: false });

        // check for invite status
        if (findInvite.status !== "pending")
          return res
            .status(409)
            .json({ message: "Invite has been used", ok: false });

        //  check for invite expiry
        if (findInvite.expiresAt < new Date())
          return res
            .status(400)
            .json({ message: "Invite has been expired!", ok: false });

        //return response to frontend
        return res.json({
          ok: true,
          invite: {
            inviteeEmail: findInvite.email,
            workspaceName: findInvite.workspaceName || "",
            role: findInvite.role,
            status: findInvite.status,
            expiresAt: findInvite.expiresAt,
            workspace: findInvite.workspaceId,
          },
          expired: false,
        });
      } catch (error) {
        console.error(error);
        return res.status(500).json({ ok: false, message: "Server error" });
      }
    });

    // accept invitation and update workspace member
    app.post("/invites/:choice", verifyToken, async (req, res) => {
      const { choice } = req.params;
      const { token } = req.body;
      const me = getUserIdentity(req);

      // check if token is sent
      if (!token)
        return res.status(400).json({ message: "Invalid Token", ok: false });

      // choice = accept/reject -> accept adds the invitee to db & reject 'revoke' the invitee status
      // accept validation check
      if (choice !== "accept" && choice !== "reject") {
        return res.status(400).json({
          ok: false,
          message: "Invalid option",
        });
      }

      // again...token hash
      const hashedToken = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

      // revoke invitee status
      if (choice === "reject") {
        const findInvitee = await inviteCollection.findOneAndUpdate(
          // find valid invitee by token, status & expires at
          {
            token: hashedToken,
            status: "pending",
            expiresAt: { $gt: new Date() },
          },
          // update status --> revoked, add revoked date
          {
            $set: {
              status: "revoked",
              revokedAt: new Date(),
            },
          },
          // return updated document
          {
            returnDocument: "after",
          },
        );

        // if revoking fails for some reason
        if (!findInvitee.value) {
          return res.status(404).json({
            ok: false,
            message: "Invite not found or already processed",
          });
        }

        // revoking response sent to frontend
        return res
          .status(200)
          .json({ message: "Invitation Rejected/Revoked", ok: true });
      }

      //  Now if the user accept the invitation...
      const userEmail = normalizeEmail(me.email);
      if (!me.id) {
        return res.status(400).json({
          message: "User id is required",
          ok: false,
        });
      }

      // find the invitation
      const findInvite = await inviteCollection.findOne({
        token: hashedToken,
        status: "pending",
      });

      //  if the invitation is not found
      if (!findInvite)
        return res
          .status(404)
          .json({ message: "Invite Not Found!", ok: false });

      // if the invitation is expired...
      if (findInvite.expiresAt < new Date()) {
        return res.status(400).json({
          message: "Invite has been expired!",
          ok: false,
        });
      }

      console.log("invitee:" + findInvite.email, "auth:" + userEmail);
      // if invitee email and user email doesn't match
      if (normalizeEmail(findInvite.email) !== userEmail)
        return res.status(403).json({
          message: `Please use ${findInvite.email} to accept the invitation `,
          ok: false,
        });
      // I don't think this block needs to exist because we already verify it once when the user is invited
      const workspaceFilter = isValidId(findInvite.workspaceId)
        ? { _id: toId(findInvite.workspaceId) }
        : { _id: null };
      const findUser = await workspacesCollection.findOne({
        ...workspaceFilter,
        "members.email": userEmail,
      });

      if (findUser)
        return res
          .status(409)
          .json({ message: "User already exist!", ok: false });

      // invitee's workspace member data
      const member = {
        id: new ObjectId().toString(),
        userId: String(me.id),
        name: me.name || userEmail.split("@")[0] || "Member",
        email: userEmail,
        role: findInvite.role,
      };

      // add invitee to the workspace db
      const addMember = await workspacesCollection.updateOne(
        { ...workspaceFilter, "members.email": { $ne: userEmail } },
        { $push: { members: member } },
      );

      // if failed to add
      if (!addMember.modifiedCount) {
        return res.status(409).json({
          message: "Could not add user to workspace",
          ok: false,
        });
      }
      // update invite collection db
      const query = await inviteCollection.findOneAndUpdate(
        { token: hashedToken, status: "pending" },
        { $set: { status: "accepted" } },
        { returnDocument: "after" },
      );

      // frontend response
      return res.json({
        message: "Invite Accepted",
        ok: true,
        query,
      });
    });

    // delete a sent invite
    app.delete(
      "/workspaces/:workspaceId/invites/:inviteId",
      verifyToken,
      async (req, res) => {
        try {
          const { workspaceId, inviteId } = req.params;
          const me = getUserIdentity(req);

          if (!isValidId(workspaceId) || !isValidId(inviteId)) {
            return res
              .status(400)
              .json({ ok: false, message: "Invalid id provided" });
          }

          const workspace = await workspacesCollection.findOne({
            _id: toId(workspaceId),
          });
          if (!workspace) {
            return res
              .status(404)
              .json({ ok: false, message: "Workspace not found" });
          }
          if (!isWorkspaceAdmin(workspace, me)) {
            return res.status(403).json({
              ok: false,
              message: "Only admin can delete invites",
            });
          }

          const result = await inviteCollection.deleteOne({
            _id: toId(inviteId),
            workspaceId,
          });
          if (!result.deletedCount) {
            return res
              .status(404)
              .json({ ok: false, message: "Invite not found" });
          }

          return res.json({
            ok: true,
            message: "Invite deleted",
          });
        } catch (error) {
          console.error(error);
          return res.status(500).json({ ok: false, message: "Server error" });
        }
      },
    );

    // Invite Feature--------->Rifat_END

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!",
    // );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Zyplo server is running!");
});

app.listen(port, () => {
  console.log(`Zyplo is listening on port ${port}`);
});

// const serverless = require("serverless-http");
// module.exports = serverless(app);
