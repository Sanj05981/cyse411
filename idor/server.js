const express = require("express");
const app = express();
const PORT = 3000;

app.disable("x-powered-by");
app.use(express.json());

const users = [
  { id: 1, name: "Alice", role: "customer", department: "north" },
  { id: 2, name: "Bob", role: "customer", department: "south" },
  { id: 3, name: "Charlie", role: "support", department: "north" },
];

const orders = [
  { id: 1, userId: 1, item: "Laptop", region: "north", total: 2000 },
  { id: 2, userId: 1, item: "Mouse", region: "north", total: 40 },
  { id: 3, userId: 2, item: "Monitor", region: "south", total: 300 },
  { id: 4, userId: 2, item: "Keyboard", region: "south", total: 60 },
];

const fakeAuth = (req, res, next) => {
  const idHeader = req.header("X-User-Id");
  const id = idHeader ? parseInt(idHeader, 10) : null;
  const user = users.find((u) => u.id === id);

  if (!user) {
    return res
      .status(401)
      .json({ error: "Unauthenticated: set X-User-Id" });
  }

  req.user = user;
  next();
};

app.use(fakeAuth);

app.get("/", (req, res) => {
  res.json({
    message: "Access Control Tutorial API",
    currentUser: req.user,
  });
});

app.get("/orders/:id", (req, res) => {
  const orderId = parseInt(req.params.id, 10);
  const order = orders.find((o) => o.id === orderId);

  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  if (order.userId !== req.user.id) {
    return res.status(403).json({ error: "Forbidden: Access denied" });
  }

  res.json(order);
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
