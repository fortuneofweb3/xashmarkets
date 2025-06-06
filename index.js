const { TwitterApi } = require('twitter-api-v2');
const cron = require('node-cron');
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const fs = require('fs').promises;
const crypto = require('crypto');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// X app credentials
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || 'https://xashmarkets.onrender.com/callback';

// Validate environment variables
if (!CLIENT_ID || !CLIENT_SECRET || !process.env.SESSION_SECRET) {
  console.error('Missing required environment variables: CLIENT_ID, CLIENT_SECRET, or SESSION_SECRET');
  process.exit(1);
}

// CORS configuration
const allowedOrigins = [
  'https://dev.fun',
  'https://cdn.dev.fun',
  'https://dev.fun/p/93ea680b334bd848c300'
];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// Middleware
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' },
  })
);

// Token storage
const TOKEN_FILE = 'tokens.json';

// Initialize token storage
async function loadTokens() {
  try {
    const data = await fs.readFile(TOKEN_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') {
      await fs.writeFile(TOKEN_FILE, '[]');
      return [];
    }
    console.error('Error loading tokens:', error.message);
    return [];
  }
}

async function saveTokens(tokens) {
  try {
    await fs.writeFile(TOKEN_FILE, JSON.stringify(tokens, null, 2));
  } catch (error) {
    console.error('Error saving tokens:', error.message);
  }
}

// Generate PKCE code verifier and challenge
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// OAuth 2.0 PKCE login
app.get('/auth/login', async (req, res) => {
  try {
    if (!CLIENT_ID || !CLIENT_SECRET) {
      throw new Error('Missing CLIENT_ID or CLIENT_SECRET');
    }
    const client = new TwitterApi({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
    
    // Verify the method exists
    if (typeof client.generateOAuth2AuthUrl !== 'function') {
      throw new Error('generateOAuth2AuthUrl is not a function in twitter-api-v2');
    }

    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    const authUrl = client.generateOAuth2AuthUrl({
      redirect_uri: REDIRECT_URI,
      scope: ['tweet.read', 'users.read', 'like.read', 'offline.access'],
      state: crypto.randomBytes(16).toString('hex'),
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    req.session.codeVerifier = codeVerifier;
    console.log('Generated auth URL:', authUrl);
    res.json({ authUrl });
  } catch (error) {
    console.error('Error in /auth/login:', error.message, error.stack);
    res.status(500).json({ error: `Error initiating OAuth 2.0: ${error.message}` });
  }
});

// OAuth 2.0 callback
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  const { codeVerifier } = req.session;

  try {
    if (!code || !codeVerifier) {
      throw new Error('Missing code or code verifier');
    }

    const client = new TwitterApi({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
    const { accessToken, refreshToken, expiresIn, client: userClient } = await client.loginWithOAuth2({
      code,
      codeVerifier,
      redirectUri: REDIRECT_URI,
    });

    const user = await userClient.v2.me({ 'user.fields': 'id,username,name' });
    const userId = user.data.id;

    const tokens = await loadTokens();
    if (!tokens.some((t) => t.userId === userId)) {
      tokens.push({ accessToken, refreshToken, expiresIn, userId, username: user.data.username, name: user.data.name, createdAt: Date.now() });
      await saveTokens(tokens);
    }

    res.redirect(`https://dev.fun?userId=${userId}&username=${encodeURIComponent(user.data.username)}`);
  } catch (error) {
    console.error('Error in /auth/callback:', error.message, error.stack);
    res.status(500).json({ error: `Error completing OAuth 2.0: ${error.message}` });
  }
});

// Get all authenticated users
app.get('/users', async (req, res) => {
  try {
    const tokens = await loadTokens();
    const users = tokens.map(({ userId, username, name }) => ({ userId, username, name }));
    res.json({ users });
  } catch (error) {
    console.error('Error in /users:', error.message, error.stack);
    res.status(500).json({ error: `Error fetching users: ${error.message}` });
  }
});

// Get liked posts for a specific user
app.get('/likes/:userId', async (req, res) => {
  const { userId } = req.params;
  let tokens = await loadTokens();
  const user = tokens.find((t) => t.userId === userId);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  let accessToken = user.accessToken;
  const isExpired = Date.now() >= user.createdAt + user.expiresIn * 1000;

  if (isExpired) {
    try {
      const client = new TwitterApi({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
      const refreshed = await refreshAccessToken(client, user.refreshToken);
      if (!refreshed) {
        return res.status(401).json({ error: `Failed to refresh token for user ID ${userId}` });
      }

      accessToken = refreshed.accessToken;
      const index = tokens.findIndex((t) => t.userId === userId);
      tokens[index] = {
        ...user,
        accessToken: refreshed.accessToken,
        refreshToken: refreshed.refreshToken,
        expiresIn: refreshed.expiresIn,
        createdAt: Date.now(),
      };
      await saveTokens(tokens);
    } catch (error) {
      console.error('Error refreshing token:', error.message, error.stack);
      return res.status(500).json({ error: `Error refreshing token: ${error.message}` });
    }
  }

  const client = new TwitterApi(accessToken).readOnly;

  try {
    const likedTweets = await client.v2.userLikedTweets(userId, {
      'tweet.fields': 'id,text,created_at,author_id',
      max_results: 10,
    });

    const tweets = await likedTweets.fetch();
    res.json({
      userId,
      likes: tweets.data || [],
      count: tweets.data ? tweets.data.length : 0,
    });
  } catch (error) {
    console.error('Error in /likes:', error.message, error.stack);
    res.status(500).json({ error: `Error fetching likes for user ID ${userId}: ${error.message}` });
  }
});

async function refreshAccessToken(client, refreshToken) {
  try {
    const { accessToken, refreshToken: newRefreshToken, expiresIn } = await client.refreshOAuth2Token(refreshToken);
    return { accessToken, refreshToken: newRefreshToken, expiresIn };
  } catch (error) {
    console.error('Error refreshing token:', error.message, error.stack);
    return null;
  }
}

async function fetchLikedTweetsForAllUsers() {
  console.log(`=== Running liked posts fetch at ${new Date().toLocaleString('en-US', { timeZone: 'Africa/Lagos' })} ===`);
  let tokens = await loadTokens();

  if (tokens.length === 0) {
    console.log('No authenticated users found.');
    return;
  }

  for (let i = 0; i < tokens.length; i++) {
    const user = tokens[i];
    let accessToken = user.accessToken;
    const isExpired = Date.now() >= user.createdAt + user.expiresIn * 1000;

    if (isExpired) {
      console.log(`Token for user ID ${user.userId} expired. Refreshing...`);
      const client = new TwitterApi({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
      const refreshed = await refreshAccessToken(client, user.refreshToken);
      if (!refreshed) {
        console.log(`Failed to refresh token for user ID ${user.userId}. Skipping.`);
        continue;
      }

      accessToken = refreshed.accessToken;
      tokens[i] = {
        ...user,
        accessToken: refreshed.accessToken,
        refreshToken: refreshed.refreshToken,
        expiresIn: refreshed.expiresIn,
        createdAt: Date.now(),
      };
      await saveTokens(tokens);
    }

    const client = new TwitterApi(accessToken).readOnly;
    try {
      console.log(`Processing user ID: ${user.userId} (${user.username})`);
      const likedTweets = await client.v2.userLikedTweets(user.userId, {
        'tweet.fields': 'id,text,created_at,author_id',
        max_results: 10,
      });

      const tweets = await likedTweets.fetch();
      if (tweets.data && tweets.data.length > 0) {
        console.log(`Found ${tweets.data.length} liked posts for user ID ${user.userId}:`);
        for (const tweet of tweets.data) {
          console.log('\nPost ID:', tweet.id);
          console.log('Created at:', tweet.created_at);
          console.log('Text:', tweet.text);
          console.log('Author ID:', tweet.author_id);
        }
      } else {
        console.log(`No liked posts found for user ID ${user.userId}.`);
      }
    } catch (error) {
      console.error(`Error for user ID ${user.userId}:`, error.message, error.stack);
    }
  }
}

// Schedule the task every 20 minutes
cron.schedule('*/20 * * * *', () => {
  console.log('Starting scheduled task to fetch liked posts...');
  fetchLikedTweetsForAllUsers();
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Visit /auth/login to authenticate a user.');
  fetchLikedTweetsForAllUsers();
});
