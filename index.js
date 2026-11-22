import express from 'express';
import cors from 'cors';
import { MongoClient, ServerApiVersion } from 'mongodb';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 8000;

// 1. CORS Configuration
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:3001',
  'http://localhost:5173',
  process.env.CLIENT_URL,
  process.env.FRONTEND_URL,
].filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like Postman, curl, or mobile tools)
      if (!origin) return callback(null, true);

      const isAllowed =
        allowedOrigins.includes(origin) ||
        origin.endsWith('.vercel.app');

      if (isAllowed) {
        return callback(null, true);
      }
      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  })
);

// 2. Body Parser Middleware
app.use(express.json());

// 3. MongoDB Client Setup
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;
export let destinationCollection;

async function connectDB() {
  try {
    await client.connect();
    db = client.db('mentorlagbe');
    destinationCollection = db.collection('destination');
    console.log('Successfully connected to MongoDB!');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
  }
}

connectDB();

// 4. Routes
app.get('/', (req, res) => {
  res.send({ status: 'ok', message: 'MentorLagbe server is running fine!' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  if (err?.message?.includes('CORS blocked')) {
    return res.status(403).json({ error: err.message });
  }
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

// 5. Start Server
app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
