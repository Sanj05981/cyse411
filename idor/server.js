const express = require("express");
const app = express();
const PORT = 3000;

// Middleware Configuration
app.disable("x-powered-by");
app.use(express.json());

// --- Data Sources ---

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

// --- Authentication Logic ---

// Validates the X-User-Id header to simulate a logged-in session
const fakeAuth = (req, res, next) => {
  const idHeader = req.header("X-User-Id");
  
  // Parse ID safely; defaults to null if header is missing
  const id = idHeader ? parseInt(idHeader, 10) : null;

  // Lookup user in our "database"
  const user = users.find((u) => u.id === id);

  if (!user) {
    return res.status(401).json({ error: "Unauthenticated: set X-User-Id" });
  }

  // Attach the found user object to the request for downstream use
  req.user = user;
  next();
};

// Enforce authentication globally
app.use(fakeAuth);

// --- Application Routes ---

// Health / Context Check
app.get("/", (req, res) => {
  res.json({ 
    message: "Access Control Tutorial API", 
    currentUser: req.user 
  });
});

/**
 * SECURE ENDPOINT: Fetch Order by ID
 * PATCHED: Added ownership verification to prevent IDOR attacks.
 */
app.get("/orders/:id", (req, res) => {
  // Convert param to integer
  const orderId = parseInt(req.params.id, 10);
  
  // 1. Lookup the resource
  const order = orders.find((o) => o.id === orderId);

  // 2. Handle non-existent resources
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  // 3. Authorization Check (The Fix)
  // Ensure the logged-in user actually owns this order.
  if (order.userId !== req.user.id) {
    return res.status(403).json({ error: "Forbidden: Access denied" });
  }

  // 4. Return data if authorized
  res.json(order);
});

// --- Server Initialization ---

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
