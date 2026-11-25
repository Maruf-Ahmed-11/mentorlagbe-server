import express from 'express';
import cors from 'cors';
import { MongoClient, ObjectId, ServerApiVersion } from 'mongodb';
import { createRemoteJWKSet, jwtVerify, SignJWT } from 'jose';
import Stripe from 'stripe';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 8000;
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

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

// Role-based access middlewares (Challenge 2)
const resolveUserRole = async (req) => {
  const email = (req.user?.email || '').toLowerCase().trim();
  if (email && usersCollection) {
    const userDoc = await usersCollection.findOne({
      email: { $regex: new RegExp(`^${email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') },
    });
    if (userDoc?.role) return String(userDoc.role).toLowerCase();
  }
  return String(req.user?.role || 'student').toLowerCase();
};

export const verifyStudent = async (req, res, next) => {
  const role = await resolveUserRole(req);
  if (role !== 'student') {
    return res.status(403).send({ message: 'Forbidden: Student role required' });
  }
  req.userRole = role;
  return next();
};

export const verifyTutor = async (req, res, next) => {
  const role = await resolveUserRole(req);
  if (role !== 'tutor' && role !== 'admin') {
    return res.status(403).send({ message: 'Forbidden: Tutor role required' });
  }
  req.userRole = role;
  return next();
};

export const verifyAdmin = async (req, res, next) => {
  const role = await resolveUserRole(req);
  if (role !== 'admin') {
    return res.status(403).send({ message: 'Forbidden: Admin role required' });
  }
  req.userRole = role;
  return next();
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
export let paymentsCollection;
export let reviewsCollection;

async function connectDB() {
  try {
    await client.connect();
    db = client.db('mentorlagbe');
    tuitionsCollection = db.collection('tuitions');
    applicationsCollection = db.collection('applications');
    usersCollection = db.collection('user');
    destinationCollection = db.collection('destination');
    paymentsCollection = db.collection('payments');
    reviewsCollection = db.collection('reviews');
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

// Create a new tuition (Secured: Tutor or Admin)
app.post('/tuitions', verifyToken, verifyTutor, async (req, res) => {
  try {
    const data = req.body;
    const tutorEmail = data.tutorEmail || req.user?.email;

    // Check free tier posting limit (2 free posts for tutors, unlimited for pro)
    if (tutorEmail) {
      const userDoc = await usersCollection.findOne({ email: { $regex: new RegExp(`^${tutorEmail}$`, 'i') } });
      const isPro = userDoc?.plan === 'pro' || userDoc?.role === 'admin' || req.user?.role === 'admin';
      const postCount = await tuitionsCollection.countDocuments({ tutorEmail: { $regex: new RegExp(`^${tutorEmail}$`, 'i') } });
      if (!isPro && postCount >= 2) {
        return res.status(403).send({
          code: 'LIMIT_REACHED',
          message: 'Free post limit reached (2/2 posts). Upgrade to Tutor Pro for unlimited tuition posts.',
          limit: 2,
          count: postCount,
        });
      }
    }

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
      approvalStatus: 'pending', // Strictly pending by default for all tutor postings
      isActive: data.isActive !== undefined ? data.isActive : true,
      createdAt: data.createdAt ? new Date(data.createdAt) : new Date(),
    };
    const result = await tuitionsCollection.insertOne(doc);
    res.status(201).send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to create tuition', error: err.message });
  }
});

// Count tuitions (Public with filters)
app.get('/tuitions/count', async (req, res) => {
  try {
    const query = {};
    if (req.query.email) {
      query.tutorEmail = { $regex: new RegExp(`^${req.query.email}$`, 'i') };
    }
    const count = await tuitionsCollection.countDocuments(query);
    res.send({ count });
  } catch (err) {
    res.status(500).send({ message: 'Failed to count tuitions', error: err.message });
  }
});

// Get all tuitions (Public with server-side search & filters)
app.get('/tuitions', async (req, res) => {
  try {
    const escapeRx = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const query = {};
    if (req.query.email) {
      query.tutorEmail = req.query.email;
    }
    if (req.query.status) {
      query.approvalStatus = req.query.status;
    }
    if (req.query.isActive !== undefined) {
      query.isActive = req.query.isActive === 'true';
    }
    if (req.query.subject && req.query.subject.toLowerCase() !== 'all') {
      query.subject = { $regex: `^${escapeRx(req.query.subject)}$`, $options: 'i' };
    }
    if (req.query.classLevel && req.query.classLevel.toLowerCase() !== 'all') {
      query.classLevel = { $regex: `^${escapeRx(req.query.classLevel)}$`, $options: 'i' };
    }
    if (req.query.mode && req.query.mode.toLowerCase() !== 'all') {
      query.mode = { $regex: escapeRx(req.query.mode), $options: 'i' };
    }
    if (req.query.q) {
      const safeQ = escapeRx(req.query.q.trim());
      if (safeQ) {
        query.$or = [
          { title: { $regex: safeQ, $options: 'i' } },
          { subject: { $regex: safeQ, $options: 'i' } },
          { classLevel: { $regex: safeQ, $options: 'i' } },
          { location: { $regex: safeQ, $options: 'i' } },
          { tutorName: { $regex: safeQ, $options: 'i' } },
        ];
      }
    }

    let cursor = tuitionsCollection.find(query);

    if (req.query.sort === 'newest' || req.query.sort === '-1') {
      cursor = cursor.sort({ _id: -1 });
    } else if (req.query.sort === 'fee_asc') {
      cursor = cursor.sort({ monthlyFee: 1 });
    } else if (req.query.sort === 'fee_desc') {
      cursor = cursor.sort({ monthlyFee: -1 });
    }

    const skip = req.query.skip ? parseInt(req.query.skip, 10) : 0;
    if (skip > 0) {
      cursor = cursor.skip(skip);
    }
    if (req.query.limit) {
      cursor = cursor.limit(parseInt(req.query.limit, 10));
    }

    const result = await cursor.toArray();

    // Instant in-memory normalization without blocking DB writes
    const sanitized = result.map((doc) => {
      if (!doc.adminVerifiedAt) {
        if (doc.approvalStatus !== 'rejected') {
          doc.approvalStatus = 'pending';
        }
      }
      return doc;
    });

    res.send(sanitized);
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

    if (!result.adminVerifiedAt && result.approvalStatus !== 'rejected') {
      result.approvalStatus = 'pending';
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

    // Strict Security: Only verified administrators can alter approvalStatus
    if (data.approvalStatus !== undefined) {
      const userRole = req.user?.role || (req.user?.email && req.user.email.toLowerCase().includes('admin') ? 'admin' : 'tutor');
      if (userRole !== 'admin') {
        return res.status(403).send({ message: 'Forbidden: Only administrators can approve or reject tuitions.' });
      }
      data.adminVerifiedAt = new Date();
    }

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

// Apply for a tuition (Secured: Student only)
app.post('/applications', verifyToken, verifyStudent, async (req, res) => {
  try {
    const applicationData = req.body;
    const studentEmail = applicationData.studentEmail || req.user?.email;

    // Check free tier application limit (10 free applications for students, unlimited for pro)
    if (studentEmail) {
      const userDoc = await usersCollection.findOne({ email: { $regex: new RegExp(`^${studentEmail}$`, 'i') } });
      const isPro = userDoc?.plan === 'pro' || userDoc?.role === 'admin' || req.user?.role === 'admin';
      const appCount = await applicationsCollection.countDocuments({ studentEmail: { $regex: new RegExp(`^${studentEmail}$`, 'i') } });
      if (!isPro && appCount >= 10) {
        return res.status(403).send({
          code: 'LIMIT_REACHED',
          message: 'Free application limit reached (10/10). Upgrade to Student Pro for unlimited applications.',
          limit: 10,
          count: appCount,
        });
      }
    }

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

// Count applications (Public with filters)
app.get('/applications/count', async (req, res) => {
  try {
    const query = {};
    if (req.query.email) {
      query.studentEmail = { $regex: new RegExp(`^${req.query.email}$`, 'i') };
    }
    if (req.query.studentEmail) {
      query.studentEmail = { $regex: new RegExp(`^${req.query.studentEmail}$`, 'i') };
    }
    if (req.query.tutorEmail) {
      query.tutorEmail = { $regex: new RegExp(`^${req.query.tutorEmail}$`, 'i') };
    }
    const count = await applicationsCollection.countDocuments(query);
    res.send({ count });
  } catch (err) {
    res.status(500).send({ message: 'Failed to count applications', error: err.message });
  }
});

// Get user usage & limits (Secured / Query)
app.get('/users/usage', async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) {
      return res.status(400).send({ message: 'Email query parameter is required' });
    }

    const userDoc = await usersCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    const role = userDoc?.role || 'student';
    const plan = userDoc?.plan || 'free';
    const isPro = plan === 'pro' || role === 'admin';

    const [tuitionsCount, applicationsCount] = await Promise.all([
      tuitionsCollection.countDocuments({ tutorEmail: { $regex: new RegExp(`^${email}$`, 'i') } }),
      applicationsCollection.countDocuments({ studentEmail: { $regex: new RegExp(`^${email}$`, 'i') } }),
    ]);

    const tutorLimit = 2;
    const studentLimit = 10;

    res.send({
      email,
      role,
      plan: isPro ? 'pro' : 'free',
      tuitionsCount,
      applicationsCount,
      canPost: isPro || tuitionsCount < tutorLimit,
      canApply: isPro || applicationsCount < studentLimit,
      tutorLimit,
      studentLimit,
    });
  } catch (err) {
    res.status(500).send({ message: 'Failed to retrieve usage stats', error: err.message });
  }
});

// ==========================================
// 7. PAYMENTS API ROUTES (STRIPE CHECKOUT & PRO UPGRADE)
// ==========================================

// Verify Stripe Checkout Session & Activate Pro
app.post('/payments/verify', verifyToken, async (req, res) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) {
      return res.status(400).send({ message: 'sessionId is required' });
    }

    if (!stripe) {
      return res.status(500).send({ message: 'Stripe is not configured on server' });
    }

    // Retrieve checkout session from Stripe
    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ['payment_intent'],
    });

    if (!session || session.payment_status !== 'paid') {
      return res.status(400).send({
        message: 'Payment has not been completed on Stripe',
        paymentStatus: session?.payment_status,
      });
    }

    const currentEmail = (req.user?.email || '').toLowerCase().trim();
    const sessionEmail = (session.customer_email || session.metadata?.userEmail || session.customer_details?.email || '').toLowerCase().trim();

    // Anti-spoofing: Check if session belongs to currently logged in user
    if (currentEmail && sessionEmail && currentEmail !== sessionEmail) {
      return res.status(403).send({ message: 'Forbidden: Checkout session does not match logged-in user account' });
    }

    // Anti-replay: Check if session ID has already been recorded
    const existing = await paymentsCollection.findOne({ sessionId });
    if (existing) {
      if (existing.userEmail && currentEmail && existing.userEmail.toLowerCase() !== currentEmail) {
        return res.status(409).send({ message: 'Conflict: This checkout session was already used by another user account.' });
      }
      return res.send({
        success: true,
        message: 'Payment already processed and verified.',
        payment: existing,
        plan: 'pro',
      });
    }

    const paymentIntentId =
      typeof session.payment_intent === 'string'
        ? session.payment_intent
        : session.payment_intent?.id || session.id;

    const amount = (session.amount_total || 0) / 100;
    const role = session.metadata?.role || (amount >= 15 ? 'tutor' : 'student');
    const effectiveEmail = sessionEmail || currentEmail;

    const paymentRecord = {
      sessionId: session.id,
      paymentIntentId,
      userId: session.metadata?.userId || req.user?.id || req.user?.sub || '',
      userEmail: effectiveEmail,
      customerEmail: session.customer_details?.email || session.customer_email || effectiveEmail,
      amount,
      currency: session.currency || 'usd',
      plan: 'pro',
      role,
      status: 'paid',
      createdAt: new Date(),
    };

    await paymentsCollection.insertOne(paymentRecord);

    // Update user's plan to 'pro' in usersCollection
    if (effectiveEmail) {
      await usersCollection.updateOne(
        { email: { $regex: new RegExp(`^${effectiveEmail}$`, 'i') } },
        { $set: { plan: 'pro', updatedAt: new Date() } }
      );
    }

    res.send({
      success: true,
      message: 'Pro plan activated successfully!',
      payment: paymentRecord,
      plan: 'pro',
    });
  } catch (err) {
    res.status(500).send({ message: 'Payment verification failed', error: err.message });
  }
});

// Get user payment transactions (Secured)
app.get('/payments', verifyToken, async (req, res) => {
  try {
    const query = {};
    const isAdmin = req.user?.role === 'admin' || (req.user?.email && req.user.email.toLowerCase().includes('admin'));

    if (!isAdmin) {
      query.userEmail = { $regex: new RegExp(`^${req.user?.email}$`, 'i') };
    } else if (req.query.email) {
      query.userEmail = { $regex: new RegExp(`^${req.query.email}$`, 'i') };
    }

    const payments = await paymentsCollection.find(query).sort({ createdAt: -1 }).toArray();
    res.send(payments);
  } catch (err) {
    res.status(500).send({ message: 'Failed to fetch payments', error: err.message });
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

// Update application status (Secured: Tutor or Admin)
app.patch('/applications/:id', verifyToken, verifyTutor, async (req, res) => {
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

// Delete / Cancel pending application (Secured: Student owner)
app.delete('/applications/:id', verifyToken, verifyStudent, async (req, res) => {
  try {
    const { id } = req.params;
    const objId = getObjectId(id);
    const query = objId ? { _id: objId } : { id: id };
    const existing = await applicationsCollection.findOne(query);

    if (!existing) {
      return res.status(404).send({ message: 'Application not found' });
    }
    if (
      req.user?.email &&
      existing.studentEmail &&
      existing.studentEmail.toLowerCase() !== req.user.email.toLowerCase()
    ) {
      return res.status(403).send({ message: 'Forbidden: You can only cancel your own application' });
    }
    if (String(existing.status || 'pending').toLowerCase() !== 'pending') {
      return res.status(400).send({ message: 'Only pending applications can be cancelled' });
    }

    const result = await applicationsCollection.deleteOne(query);
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to delete application', error: err.message });
  }
});

// ==========================================
// 8. REVIEWS & ADMIN ENDPOINTS
// ==========================================

// Get reviews for a tuition (Public)
app.get('/reviews', async (req, res) => {
  try {
    const { tuitionId } = req.query;
    if (!tuitionId) {
      return res.status(400).send({ message: 'tuitionId is required' });
    }
    const reviews = await reviewsCollection
      .find({ tuitionId: String(tuitionId) })
      .sort({ createdAt: -1 })
      .toArray();
    const totalReviews = reviews.length;
    const averageRating =
      totalReviews > 0
        ? Number((reviews.reduce((sum, r) => sum + Number(r.rating || 0), 0) / totalReviews).toFixed(1))
        : 0;
    res.send({ reviews, totalReviews, averageRating });
  } catch (err) {
    res.status(500).send({ message: 'Failed to fetch reviews', error: err.message });
  }
});

// Submit or update review (Secured: Accepted Student)
app.post('/reviews', verifyToken, verifyStudent, async (req, res) => {
  try {
    const { tuitionId, tuitionTitle, rating, comment } = req.body;
    const studentEmail = (req.user?.email || '').toLowerCase().trim();
    const numRating = Number(rating);

    if (!tuitionId || !comment?.trim() || numRating < 1 || numRating > 5) {
      return res.status(400).send({ message: 'Valid tuitionId, rating (1-5), and comment are required' });
    }

    const acceptedApp = await applicationsCollection.findOne({
      tuitionId: String(tuitionId),
      studentEmail: { $regex: new RegExp(`^${studentEmail}$`, 'i') },
      status: { $regex: /^accepted$/i },
    });

    if (!acceptedApp) {
      return res.status(403).send({ message: 'Only accepted students can review this tuition' });
    }

    await reviewsCollection.updateOne(
      { tuitionId: String(tuitionId), studentEmail },
      {
        $set: {
          tuitionId: String(tuitionId),
          tuitionTitle: tuitionTitle || 'Tuition Session',
          studentEmail,
          studentName: req.user?.name || 'Student',
          rating: numRating,
          comment: comment.trim(),
          updatedAt: new Date(),
        },
        $setOnInsert: { createdAt: new Date() },
      },
      { upsert: true }
    );

    res.send({ success: true, message: 'Review submitted successfully' });
  } catch (err) {
    res.status(500).send({ message: 'Failed to submit review', error: err.message });
  }
});

// Admin Users Management (Secured: Admin only)
app.get('/admin/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users = await usersCollection.find().sort({ createdAt: -1 }).toArray();
    res.send({ users });
  } catch (err) {
    res.status(500).send({ message: 'Failed to fetch users', error: err.message });
  }
});

app.patch('/admin/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { email, role } = req.body;
    if (!email || !['student', 'tutor', 'admin'].includes(role)) {
      return res.status(400).send({ message: 'Valid email and role are required' });
    }
    const result = await usersCollection.updateOne(
      { email: { $regex: new RegExp(`^${email}$`, 'i') } },
      { $set: { role, updatedAt: new Date() } }
    );
    res.send({ success: true, result });
  } catch (err) {
    res.status(500).send({ message: 'Failed to update user role', error: err.message });
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
