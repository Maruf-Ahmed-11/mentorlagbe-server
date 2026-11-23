import express from 'express';
import cors from 'cors';
import { MongoClient, ObjectId, ServerApiVersion } from 'mongodb';
import { createRemoteJWKSet, jwtVerify, SignJWT } from 'jose';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 8000;
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';

// ==========================================
// 1. CORS CONFIGURATION
// Configured strictly for Frontend (localhost:3000 locally, CLIENT_URL on deploy)
// ==========================================
app.use(
  cors({
    origin: [CLIENT_URL],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  })
);

app.use(express.json());

// ==========================================
// 2. REMOTE JWKS & JWT VERIFICATION MIDDLEWARE
// Verifies tokens using Remote JWKS (from Better-Auth) with fallback to JWT_SECRET
// ==========================================
const jwksUrl = new URL('/api/auth/jwks', CLIENT_URL);
const JWKS = createRemoteJWKSet(jwksUrl);

export const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader) {
    return res.status(401).send({ message: 'Unauthorized access: No token provided' });
  }

  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : authHeader.trim();

  if (!token) {
    return res.status(401).send({ message: 'Unauthorized access: Invalid token format' });
  }

  try {
    // 1. Primary: Verify against Better-Auth Remote JWKS
    const { payload } = await jwtVerify(token, JWKS);
    req.user = payload;
    req.token = token;
    return next();
  } catch (jwksErr) {
    // 2. Fallback: Verify with HS256 secret if JWT_SECRET is configured
    if (process.env.JWT_SECRET) {
      try {
        const secret = new TextEncoder().encode(process.env.JWT_SECRET);
        const { payload } = await jwtVerify(token, secret);
        req.user = payload;
        req.token = token;
        return next();
      } catch (secretErr) {
        return res.status(401).send({
          message: 'Unauthorized access: Invalid or expired token',
          error: jwksErr.message,
        });
      }
    }

    return res.status(401).send({
      message: 'Unauthorized access: Invalid or expired token',
      error: jwksErr.message,
    });
  }
};

// ==========================================
// 3. DATABASE SETUP & COLLECTIONS
// ==========================================
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;
export let tuitionsCollection;
export let applicationsCollection;
export let usersCollection;
export let destinationCollection;

async function connectDB() {
  try {
    await client.connect();
    db = client.db('mentorlagbe');
    tuitionsCollection = db.collection('tuitions');
    applicationsCollection = db.collection('applications');
    usersCollection = db.collection('user');
    destinationCollection = db.collection('destination');
    console.log('Successfully connected to MongoDB (mentorlagbe)!');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
  }
}

connectDB();

const getObjectId = (id) => {
  try {
    return new ObjectId(id);
  } catch {
    return null;
  }
};

// ==========================================
// 4. JWT TOKEN GENERATION ENDPOINT
// ==========================================
app.post('/jwt', async (req, res) => {
  try {
    const user = req.body;
    if (!process.env.JWT_SECRET) {
      return res.status(500).send({ message: 'JWT_SECRET is not configured on server' });
    }
    const secret = new TextEncoder().encode(process.env.JWT_SECRET);
    const token = await new SignJWT(user)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1d')
      .sign(secret);

    res.send({ token });
  } catch (err) {
    res.status(500).send({ message: 'Failed to generate token', error: err.message });
  }
});

// ==========================================
// 5. TUITIONS API ROUTES
// ==========================================

// Create a new tuition (Secured)
app.post('/tuitions', verifyToken, async (req, res) => {
  try {
    const data = req.body;

    // Reject exact duplicate tuition postings for the same tutor
    if (data.tutorEmail && data.title && data.subject) {
      const existing = await tuitionsCollection.findOne({
        tutorEmail: data.tutorEmail,
        title: { $regex: new RegExp(`^${data.title.trim()}$`, 'i') },
        subject: data.subject,
        classLevel: data.classLevel,
      });
      if (existing) {
        return res.status(409).send({ message: 'A tuition listing with this exact title and subject already exists.' });
      }
    }

    const doc = {
      ...data,
      monthlyFee: Number(data.monthlyFee) || 0,
      approvalStatus: data.approvalStatus || 'pending',
      isActive: data.isActive !== undefined ? data.isActive : true,
      createdAt: data.createdAt ? new Date(data.createdAt) : new Date(),
    };
    const result = await tuitionsCollection.insertOne(doc);
    res.status(201).send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to create tuition', error: err.message });
  }
});

// Get all tuitions (Public with filters)
app.get('/tuitions', async (req, res) => {
  try {
    const query = {};
    if (req.query.email) {
      query.tutorEmail = req.query.email;
    }
    if (req.query.status) {
      query.approvalStatus = req.query.status;
    }
    if (req.query.subject) {
      query.subject = { $regex: req.query.subject, $options: 'i' };
    }

    let cursor = tuitionsCollection.find(query);

    if (req.query.sort === 'newest' || req.query.sort === '-1') {
      cursor = cursor.sort({ _id: -1 });
    } else if (req.query.sort === 'fee_asc') {
      cursor = cursor.sort({ monthlyFee: 1 });
    } else if (req.query.sort === 'fee_desc') {
      cursor = cursor.sort({ monthlyFee: -1 });
    }

    if (req.query.limit) {
      cursor = cursor.limit(parseInt(req.query.limit, 10));
    }

    const result = await cursor.toArray();
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to fetch tuitions', error: err.message });
  }
});

// Get single tuition by ID (Public)
app.get('/tuitions/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const objId = getObjectId(id);
    const query = objId ? { $or: [{ _id: objId }, { id: id }] } : { id: id };
    const result = await tuitionsCollection.findOne(query);

    if (!result) {
      return res.status(404).send({ message: 'Tuition not found' });
    }
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to fetch tuition', error: err.message });
  }
});

// Update a tuition (Secured)
app.patch('/tuitions/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const data = { ...req.body };
    delete data._id;

    const objId = getObjectId(id);
    const query = objId ? { $or: [{ _id: objId }, { id: id }] } : { id: id };

    const result = await tuitionsCollection.updateOne(query, { $set: data });
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to update tuition', error: err.message });
  }
});

// Delete a tuition (Secured)
app.delete('/tuitions/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const objId = getObjectId(id);
    const query = objId ? { $or: [{ _id: objId }, { id: id }] } : { id: id };

    const result = await tuitionsCollection.deleteOne(query);
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to delete tuition', error: err.message });
  }
});

// ==========================================
// 6. APPLICATIONS API ROUTES
// ==========================================

// Apply for a tuition (Secured)
app.post('/applications', verifyToken, async (req, res) => {
  try {
    const applicationData = req.body;

    const existing = await applicationsCollection.findOne({
      tuitionId: applicationData.tuitionId,
      studentEmail: applicationData.studentEmail,
    });

    if (existing) {
      return res.status(400).send({ message: 'You have already applied for this tuition!' });
    }

    const doc = {
      ...applicationData,
      status: applicationData.status || 'pending',
      appliedAt: new Date(),
    };

    const result = await applicationsCollection.insertOne(doc);
    res.status(201).send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to submit application', error: err.message });
  }
});

// Get applications (Secured)
app.get('/applications', verifyToken, async (req, res) => {
  try {
    const query = {};
    if (req.query.studentEmail) query.studentEmail = req.query.studentEmail;
    if (req.query.tutorEmail) query.tutorEmail = req.query.tutorEmail;
    if (req.query.tuitionId) query.tuitionId = req.query.tuitionId;

    const result = await applicationsCollection.find(query).sort({ appliedAt: -1 }).toArray();
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to fetch applications', error: err.message });
  }
});

// Update application status (Secured)
app.patch('/applications/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const objId = getObjectId(id);
    const query = objId ? { _id: objId } : { id: id };

    const result = await applicationsCollection.updateOne(query, {
      $set: { status, updatedAt: new Date() },
    });
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to update application', error: err.message });
  }
});

// Delete application (Secured)
app.delete('/applications/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const objId = getObjectId(id);
    const query = objId ? { _id: objId } : { id: id };

    const result = await applicationsCollection.deleteOne(query);
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to delete application', error: err.message });
  }
});

// ==========================================
// 7. ROOT / HEALTH CHECK & ERROR HANDLING
// ==========================================
app.get('/', (req, res) => {
  res.send({ status: 'ok', message: 'MentorLagbe server is running fine!' });
});

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ message: 'Invalid JSON payload' });
  }
  if (err?.message?.includes('CORS blocked')) {
    return res.status(403).json({ error: err.message });
  }
  console.error(err.stack || err);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});

export default app;
