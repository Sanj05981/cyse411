const express = require("express");
const server = express();
const PORT = 3000;

server.disable("x-powered-by");
server.use(express.json());

// In-memory mock data
const USERS = [
  { id: 1, name: "Alice", role: "customer", department: "north" },
  { id: 2, name: "Bob", role: "customer", department: "south" },
  { id: 3, name: "Charlie", role: "support", department: "north" },
];

const ORDERS = [
  { id: 1, userId: 1, item: "Laptop", region: "north", total: 2000 },
  { id: 2, userId: 1, item: "Mouse", region: "north", total: 40 },
  { id: 3, userId: 2, item: "Monitor", region: "south", total: 300 },
  { id: 4, userId: 2, item: "Keyboard", region: "south", total: 60 },
];

// Simple header-based auth middleware
function authenticate(req, res, next) {
  const rawId = req.get("X-User-Id");
  const uid = Number(rawId);

  const matchedUser = USERS.find((u) => u.id === uid);

  if (!matchedUser) {
    return res.status(401).json({ error: "Authentication required" });
  }

  req.currentUser = matchedUser;
  next();
}

server.use(authenticate);

// Home route for debugging
server.get("/", (req, res) => {
  res.json({
    status: "API OK",
    user: req.currentUser,
  });
});

// Secure order lookup
server.get("/orders/:orderId", (req, res) => {
  const requestedId = Number(req.params.orderId);

  const orderRecord = ORDERS.find((o) => o.id === requestedId);

  if (!orderRecord) {
    return res.status(404).json({ error: "Order does not exist" });
  }

  // Prevent IDOR — users can only view their own orders
  const userOwnsOrder = orderRecord.userId === req.currentUser.id;

  if (!userOwnsOrder) {
    return res.status(403).json({ error: "Access forbidden" });
  }

  res.json(orderRecord);
});

// Start server
server.listen(PORT, () => {
  console.log(`Listening on http://localhost:${PORT}`);
});
