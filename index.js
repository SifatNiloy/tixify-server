const express = require("express");
const app = express();
require("dotenv").config();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { MongoClient, ObjectId } = require("mongodb");
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// JWT verification middleware
const verifyJWT = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res
      .status(401)
      .send({ error: true, message: "Unauthorized access" });
  }
  const token = authorization.split(" ")[1];
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).send({ error: true, message: "Forbidden access" });
    }
    req.decoded = decoded;
    next();
  });
};

// MongoDB connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nlpzidc.mongodb.net/tixify?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri);

async function run() {
  try {
    await client.connect();
    const db = client.db("tixify");
    const usersCollection = db.collection("users");
    const eventsCollection = db.collection("events");
    const bookingsCollection = db.collection("bookings");
    const paymentsCollection = db.collection("payments");

    // JWT token generation
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "24h",
      });
      res.send(token);
    });

    // User registration
    app.post("/users", async (req, res) => {
      const user = req.body;
      const existingUser = await usersCollection.findOne({ email: user.email });
      if (existingUser) {
        return res.send({ message: "User already exists" });
      }
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    // Save user data from social login
    app.post("/saveUser", async (req, res) => {
      const user = req.body;
      try {
        const existingUser = await usersCollection.findOne({
          email: user.email,
        });
        if (existingUser) {
          return res.send({ message: "User already exists" });
        }
        const result = await usersCollection.insertOne(user);
        res.status(200).send(result);
      } catch (error) {
        console.error("Error saving user:", error);
        res.status(500).send("Server error");
      }
    });

    app.get("/saveUser", async (req, res) => {
      try {
        const users = await usersCollection.find().toArray();
        res.json(users);
      } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).send("Server error");
      }
    });

    // Admin role verification
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const user = await usersCollection.findOne({ email });
      if (user?.role !== "Admin") {
        return res
          .status(403)
          .send({ error: true, message: "Forbidden access" });
      }
      next();
    };

    // Retrieve all users (admin only)
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const users = await usersCollection.find().toArray();
      res.send(users);
    });

    // Delete a user (admin only)
    app.delete("/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const result = await usersCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // Promote a user to admin (admin only)
    app.patch("/users/admin/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const result = await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { role: "Admin" } }
      );
      res.send(result);
    });

    // Check if a user is an admin
    app.get("/users/admin/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (req.decoded.email !== email) {
        return res.send({ admin: false });
      }
      const user = await usersCollection.findOne({ email });
      res.send({ admin: user?.role === "Admin" });
    });

    // Retrieve all events
    app.get("/events", async (req, res) => {
      try {
        const events = await eventsCollection.find().toArray();
        res.json(events);
      } catch (error) {
        console.error("Error fetching events:", error);
        res.status(500).send("Server error");
      }
    });

    // Retrieve a specific event
    app.get("/events/:eventId", async (req, res) => {
      const { eventId } = req.params;

      try {
        const event = await eventsCollection.findOne({
          _id: new ObjectId(eventId),
        });

        if (!event) {
          return res.status(404).send("Event not found");
        }

        res.json(event);
      } catch (error) {
        console.error("Error fetching event:", error);
        res.status(500).send("Server error");
      }
    });

    // Create a new event (admin only)
    app.post("/events", verifyJWT, verifyAdmin, async (req, res) => {
      const event = req.body;
      const result = await eventsCollection.insertOne(event);
      res.send(result);
    });

    // Update an event (admin only)
    app.put("/events/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const updatedEvent = req.body;
      const result = await eventsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updatedEvent }
      );
      res.send(result);
    });

    // Deleting an event (admin only)
    app.delete("/events/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const result = await eventsCollection.deleteOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    // Retrieving bookings for a specific event
    app.get("/bookings/event/:eventId", verifyJWT, async (req, res) => {
      try {
        const eventId = req.params.eventId;
        const bookings = await bookingsCollection
          .find({ eventId: new ObjectId(eventId) })
          .toArray();
        res.json(bookings);
      } catch (error) {
        console.error("Error fetching bookings:", error);
        res.status(500).send("Server error");
      }
    });

    // Retrieving all bookings for a user
    app.get("/bookings", verifyJWT, async (req, res) => {
      try {
        const email = req.decoded.email;
        const bookings = await bookingsCollection.find({ email }).toArray();
        res.json(bookings);
      } catch (error) {
        console.error("Error fetching bookings:", error);
        res.status(500).send("Server error");
      }
    });

    // Creating a new booking
    app.post("/bookings", verifyJWT, async (req, res) => {
      try {
        const booking = req.body;
        const result = await bookingsCollection.insertOne(booking);
        res.send(result);
      } catch (error) {
        console.error("Error creating booking:", error);
        res.status(500).send("Server error");
      }
    });

    // Deleting a booking
    app.delete("/bookings/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await bookingsCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      } catch (error) {
        console.error("Error deleting booking:", error);
        res.status(500).send("Server error");
      }
    });

    // Processing a payment
    app.post("/payments", verifyJWT, async (req, res) => {
      try {
        const payment = req.body;
        
        const result = await paymentsCollection.insertOne(payment);
        res.send(result);
      } catch (error) {
        console.error("Error processing payment:", error);
        res.status(500).send("Server error");
      }
    });

    // Starting Express server
    app.get("/", (req, res) => {
      res.send("Server connected successfully.");
    });

    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (error) {
    console.error("Error running the server:", error);
    process.exit(1);
  }
}

run().catch(console.error);
