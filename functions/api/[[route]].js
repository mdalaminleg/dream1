// functions/api/[[route]].js
const JWT_SECRET = 'reverb_super_secret_hmac_key_change_in_production';
const JWT_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;

// ---------- crypto utils ----------
async function sha256(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signToken(payload) {
  payload.exp = Date.now() + JWT_EXPIRY_MS;
  const encoder = new TextEncoder();
  const toSign = JSON.stringify(payload);
  const key = await crypto.subtle.importKey('raw', encoder.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(toSign));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `${btoa(toSign)}.${sigB64}`;
}

async function verifyToken(token) {
  try {
    const [payloadB64, sigB64] = token.split('.');
    const payloadStr = atob(payloadB64);
    const payload = JSON.parse(payloadStr);
    if (payload.exp < Date.now()) return null;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBin = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBin, new TextEncoder().encode(payloadStr));
    return valid ? payload : null;
  } catch { return null; }
}

async function getUser(request, db) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const payload = await verifyToken(token);
  if (!payload) return null;
  const user = await db.prepare('SELECT id, email, name, role, avatar_url, bio, mood, is_verified, is_approved, is_banned FROM users WHERE id = ?').bind(payload.id).first();
  return user;
}

// ---------- helpers ----------
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { 
    status, 
    headers: { 
      'Content-Type': 'application/json', 
      'Access-Control-Allow-Origin': '*', 
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', 
      'Access-Control-Allow-Headers': 'Content-Type,Authorization' 
    } 
  });
}
function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// ---------- profanity filter ----------
let cachedBadWords = null;
async function loadBadWords(db) {
  if (cachedBadWords) return cachedBadWords;
  const result = await db.prepare('SELECT word FROM banned_words').all();
  cachedBadWords = result.results.map(r => r.word.toLowerCase());
  return cachedBadWords;
}
async function hasProfanity(text, db) {
  if (!text) return false;
  const lower = text.toLowerCase();
  const words = await loadBadWords(db);
  for (const w of words) {
    if (lower.includes(w)) return true;
  }
  return false;
}
async function autoBanUser(userId, db, reason) {
  await db.prepare('UPDATE users SET is_banned = 1, is_approved = 0 WHERE id = ?').bind(userId).run();
  await db.prepare('DELETE FROM posts WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM likes WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM comments WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM echoes WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM reposts WHERE user_id = ?').bind(userId).run();
}

// ---------- pruning jobs ----------
async function runPruning(db) {
  const now = Math.floor(Date.now() / 1000);
  await db.prepare('DELETE FROM posts WHERE expires_at IS NOT NULL AND expires_at < ?').bind(now).run();
  const cutoff = now - 14 * 86400;
  await db.prepare('DELETE FROM posts WHERE like_count + comment_count + echo_count = 0 AND created_at < ?').bind(cutoff).run();
  await db.prepare('DELETE FROM likes WHERE created_at < ?').bind(now - 60 * 86400).run();
  await db.prepare('DELETE FROM comments WHERE created_at < ?').bind(now - 60 * 86400).run();
  await db.prepare('DELETE FROM echoes WHERE created_at < ?').bind(now - 30 * 86400).run();
  await db.prepare('DELETE FROM notifications WHERE created_at < ?').bind(now - 30 * 86400).run();
  await db.prepare('DELETE FROM whispers WHERE expires_at < ?').bind(now).run();
}

// ---------- database initialization ----------
async function ensureTables(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE,
    name TEXT,
    password_hash TEXT,
    role TEXT DEFAULT 'user',
    avatar_url TEXT,
    bio TEXT,
    mood INTEGER DEFAULT 0,
    device_fingerprint TEXT,
    is_approved INTEGER DEFAULT 0,
    is_banned INTEGER DEFAULT 0,
    is_verified INTEGER DEFAULT 0,
    created_at INTEGER
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    content TEXT,
    image_url TEXT,
    like_count INTEGER DEFAULT 0,
    comment_count INTEGER DEFAULT 0,
    echo_count INTEGER DEFAULT 0,
    repost_count INTEGER DEFAULT 0,
    is_capsule INTEGER DEFAULT 0,
    expires_at INTEGER,
    created_at INTEGER,
    updated_at INTEGER
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY, user_id INTEGER, post_id INTEGER, created_at INTEGER, UNIQUE(user_id, post_id)
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY, user_id INTEGER, post_id INTEGER, content TEXT, created_at INTEGER
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS echoes (
    id INTEGER PRIMARY KEY, user_id INTEGER, post_id INTEGER, created_at INTEGER, UNIQUE(user_id, post_id)
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS reposts (
    id INTEGER PRIMARY KEY, user_id INTEGER, original_post_id INTEGER, quote_text TEXT, created_at INTEGER
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS follows (
    id INTEGER PRIMARY KEY, follower_id INTEGER, followee_id INTEGER, created_at INTEGER, UNIQUE(follower_id, followee_id)
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY, user_id INTEGER, type TEXT, actor_id INTEGER, post_id INTEGER, read INTEGER DEFAULT 0, created_at INTEGER
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS hashtags (
    id INTEGER PRIMARY KEY, tag TEXT UNIQUE
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS post_hashtags (
    post_id INTEGER, hashtag_id INTEGER, PRIMARY KEY(post_id, hashtag_id)
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS mentions (
    id INTEGER PRIMARY KEY, post_id INTEGER, mentioned_user_id INTEGER, created_at INTEGER
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS whispers (
    id INTEGER PRIMARY KEY, recipient_id INTEGER, content TEXT, answer TEXT, created_at INTEGER, expires_at INTEGER
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS banned_words (
    id INTEGER PRIMARY KEY, word TEXT UNIQUE, language TEXT
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value TEXT
  )`).run();

  // Indexes
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_likes_post_id ON likes(post_id)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower_id)').run();

  // Seed banned words
  const defaultWords = [
    'fuck','shit','cunt','motherfucker','vagina','porn','xxx','hacker','anal','doggy','cock','dick','pussy','whore','slut',
    'চুদি','চোদাচুদি','মাদারচোদ','চোদা','হিজলা','বাংলা','চুদি'
  ];
  for (const w of defaultWords) {
    await db.prepare('INSERT OR IGNORE INTO banned_words (word, language) VALUES (?, ?)').bind(w, 'auto').run();
  }

  // Seed admin
  const adminEmail = 'alamin@mail.com';
  const adminPassHash = await sha256('admin3211');
  await db.prepare(`INSERT OR IGNORE INTO users (email, name, password_hash, role, is_approved, is_verified, created_at) 
    VALUES (?, 'Admin', ?, 'admin', 1, 1, ?)`).bind(adminEmail, adminPassHash, Math.floor(Date.now()/1000)).run();

  // Seed settings
  await db.prepare(`INSERT OR IGNORE INTO settings (key, value) VALUES ('imgbb_api_key', '')`).run();

  // Run pruning occasionally
  if (Math.random() < 0.01) await runPruning(db);
}

// ---------- API handlers ----------
async function handleAuth(method, path, body, db) {
  if (method === 'POST' && path === '/auth/register') {
    const { email, name, password, fingerprint } = body;
    if (!email || !name || !password) return err('Missing fields');
    if (await hasProfanity(email, db) || await hasProfanity(password, db) || await hasProfanity(name, db)) {
      return err('Inappropriate email, name, or password', 400);
    }
    const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existing) return err('Email already exists', 400);
    const fpCheck = await db.prepare('SELECT id FROM users WHERE device_fingerprint = ?').bind(fingerprint).first();
    if (fpCheck) return err('One account per device', 403);
    const hash = await sha256(password);
    const now = Math.floor(Date.now() / 1000);
    await db.prepare('INSERT INTO users (email, name, password_hash, device_fingerprint, is_approved, created_at) VALUES (?, ?, ?, ?, 0, ?)')
      .bind(email, name, hash, fingerprint, now).run();
    return json({ message: 'Registered. Await admin approval.' }, 201);
  }

  if (method === 'POST' && path === '/auth/login') {
    const { email, password } = body;
    const user = await db.prepare('SELECT id, email, name, role, password_hash, is_approved, is_banned FROM users WHERE email = ?').bind(email).first();
    if (!user) return err('Invalid credentials', 401);
    if (user.is_banned) return err('Account banned', 403);
    if (user.is_approved !== 1 && user.role !== 'admin') return err('Awaiting admin approval', 403);
    const hash = await sha256(password);
    if (hash !== user.password_hash) return err('Invalid credentials', 401);
    const token = await signToken({ id: user.id, email: user.email, role: user.role });
    return json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  }

  return null;
}

async function handleUser(method, path, body, db, user, request) {
  if (!user || (user.is_banned && user.role !== 'admin')) return err('Unauthorized', 401);

  // Get current user
  if (method === 'GET' && path === '/user/me') {
    return json(user);
  }

  // Update mood
  if (method === 'PUT' && path === '/user/mood') {
    const { mood } = body;
    if (mood < 0 || mood > 6) return err('Invalid mood');
    await db.prepare('UPDATE users SET mood = ? WHERE id = ?').bind(mood, user.id).run();
    return json({ success: true });
  }

  // Update avatar/bio
  if (method === 'PUT' && path === '/user/profile') {
    const { avatar_url, bio } = body;
    if (avatar_url) await db.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').bind(avatar_url, user.id).run();
    if (bio !== undefined) await db.prepare('UPDATE users SET bio = ? WHERE id = ?').bind(bio, user.id).run();
    return json({ success: true });
  }

  // Get user profile
  if (method === 'GET' && path.match(/^\/user\/profile\/(\d+)$/)) {
    const id = parseInt(path.split('/').pop());
    const profile = await db.prepare('SELECT id, name, avatar_url, bio, mood, is_verified FROM users WHERE id = ?').bind(id).first();
    if (!profile) return err('Not found', 404);
    return json(profile);
  }

  // Follow/unfollow
  if (method === 'POST' && path === '/user/follow') {
    const { followeeId } = body;
    if (followeeId === user.id) return err('Cannot follow self');
    const now = Math.floor(Date.now() / 1000);
    const existing = await db.prepare('SELECT id FROM follows WHERE follower_id = ? AND followee_id = ?').bind(user.id, followeeId).first();
    if (existing) {
      await db.prepare('DELETE FROM follows WHERE follower_id = ? AND followee_id = ?').bind(user.id, followeeId).run();
      return json({ following: false });
    } else {
      await db.prepare('INSERT INTO follows (follower_id, followee_id, created_at) VALUES (?, ?, ?)').bind(user.id, followeeId, now).run();
      return json({ following: true });
    }
  }

  // Feed
  if (method === 'GET' && path === '/feed') {
    const url = new URL(request.url);
    const limit = parseInt(url.searchParams.get('limit') || '20');
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const follows = await db.prepare('SELECT followee_id FROM follows WHERE follower_id = ?').bind(user.id).all();
    const followIds = follows.results.map(f => f.followee_id);
    followIds.push(user.id);
    if (followIds.length === 0) return json({ posts: [] });
    const placeholders = followIds.map(() => '?').join(',');
    const posts = await db.prepare(`
      SELECT p.*, u.name, u.avatar_url, u.is_verified 
      FROM posts p 
      JOIN users u ON p.user_id = u.id 
      WHERE p.user_id IN (${placeholders}) 
      ORDER BY p.created_at DESC 
      LIMIT ? OFFSET ?
    `).bind(...followIds, limit, offset).all();
    return json({ posts: posts.results });
  }

  // Create post
  if (method === 'POST' && path === '/posts') {
    const { content, imageUrl, isCapsule, expiresInDays } = body;
    if (!content && !imageUrl) return err('Content or image required');
    if (user.role !== 'admin') {
      const todayStart = Math.floor(new Date().setHours(0,0,0,0) / 1000);
      const count = await db.prepare('SELECT COUNT(*) as cnt FROM posts WHERE user_id = ? AND created_at >= ?').bind(user.id, todayStart).first();
      if (count.cnt >= 5) return err('Daily post limit reached (5)', 429);
    }
    if (user.role !== 'admin' && (await hasProfanity(content, db))) {
      await autoBanUser(user.id, db, 'Profanity in post');
      return err('You have been banned for inappropriate content', 403);
    }
    const now = Math.floor(Date.now() / 1000);
    let expiresAt = null;
    if (isCapsule && expiresInDays) {
      expiresAt = now + expiresInDays * 86400;
    }
    const result = await db.prepare(`
      INSERT INTO posts (user_id, content, image_url, is_capsule, expires_at, created_at, updated_at) 
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(user.id, content, imageUrl, isCapsule ? 1 : 0, expiresAt, now, now).run();
    
    const postId = result.meta.last_row_id;
    
    // Extract hashtags
    const hashtags = content.match(/#[\w\u0590-\u065F\u0660-\u06FF]+/g) || [];
    for (const tag of hashtags) {
      const tagClean = tag.slice(1).toLowerCase();
      let ht = await db.prepare('SELECT id FROM hashtags WHERE tag = ?').bind(tagClean).first();
      if (!ht) {
        const insert = await db.prepare('INSERT INTO hashtags (tag) VALUES (?) RETURNING id').bind(tagClean).first();
        ht = insert || await db.prepare('SELECT id FROM hashtags WHERE tag = ?').bind(tagClean).first();
      }
      if (ht) await db.prepare('INSERT OR IGNORE INTO post_hashtags (post_id, hashtag_id) VALUES (?, ?)').bind(postId, ht.id).run();
    }
    
    // Extract mentions
    const mentions = content.match(/@(\w+)/g) || [];
    for (const mention of mentions) {
      const username = mention.slice(1);
      const mentionedUser = await db.prepare('SELECT id FROM users WHERE name = ?').bind(username).first();
      if (mentionedUser && mentionedUser.id !== user.id) {
        await db.prepare('INSERT INTO mentions (post_id, mentioned_user_id, created_at) VALUES (?, ?, ?)').bind(postId, mentionedUser.id, now).run();
        await db.prepare('INSERT INTO notifications (user_id, type, actor_id, post_id, created_at) VALUES (?, ?, ?, ?, ?)')
          .bind(mentionedUser.id, 'mention', user.id, postId, now).run();
      }
    }
    
    return json({ id: postId });
  }

  // Delete post
  if (method === 'DELETE' && path.match(/^\/posts\/(\d+)$/)) {
    const postId = parseInt(path.split('/').pop());
    const post = await db.prepare('SELECT user_id FROM posts WHERE id = ?').bind(postId).first();
    if (!post) return err('Not found', 404);
    if (post.user_id !== user.id && user.role !== 'admin') return err('Forbidden', 403);
    await db.prepare('DELETE FROM posts WHERE id = ?').bind(postId).run();
    return json({ success: true });
  }

  // Like/unlike
  if (method === 'POST' && path.match(/^\/posts\/(\d+)\/like$/)) {
    const postId = parseInt(path.split('/')[2]);
    const now = Math.floor(Date.now() / 1000);
    const existing = await db.prepare('SELECT id FROM likes WHERE user_id = ? AND post_id = ?').bind(user.id, postId).first();
    if (existing) {
      await db.prepare('DELETE FROM likes WHERE user_id = ? AND post_id = ?').bind(user.id, postId).run();
      await db.prepare('UPDATE posts SET like_count = like_count - 1 WHERE id = ?').bind(postId).run();
      return json({ liked: false });
    } else {
      await db.prepare('INSERT INTO likes (user_id, post_id, created_at) VALUES (?, ?, ?)').bind(user.id, postId, now).run();
      await db.prepare('UPDATE posts SET like_count = like_count + 1 WHERE id = ?').bind(postId).run();
      const postOwner = await db.prepare('SELECT user_id FROM posts WHERE id = ?').bind(postId).first();
      if (postOwner && postOwner.user_id !== user.id) {
        await db.prepare('INSERT INTO notifications (user_id, type, actor_id, post_id, created_at) VALUES (?, ?, ?, ?, ?)')
          .bind(postOwner.user_id, 'like', user.id, postId, now).run();
      }
      return json({ liked: true });
    }
  }

  // Echo
  if (method === 'POST' && path.match(/^\/posts\/(\d+)\/echo$/)) {
    const postId = parseInt(path.split('/')[2]);
    if (user.role !== 'admin') {
      const todayStart = Math.floor(new Date().setHours(0,0,0,0) / 1000);
      const echoCount = await db.prepare('SELECT COUNT(*) as cnt FROM echoes WHERE user_id = ? AND created_at >= ?').bind(user.id, todayStart).first();
      if (echoCount.cnt >= 3) return err('Daily echo limit reached (3)', 429);
    }
    const existing = await db.prepare('SELECT id FROM echoes WHERE user_id = ? AND post_id = ?').bind(user.id, postId).first();
    if (existing) return err('Already echoed', 400);
    const now = Math.floor(Date.now() / 1000);
    await db.prepare('INSERT INTO echoes (user_id, post_id, created_at) VALUES (?, ?, ?)').bind(user.id, postId, now).run();
    await db.prepare('UPDATE posts SET echo_count = echo_count + 1 WHERE id = ?').bind(postId).run();
    const postOwner = await db.prepare('SELECT user_id FROM posts WHERE id = ?').bind(postId).first();
    if (postOwner && postOwner.user_id !== user.id) {
      await db.prepare('INSERT INTO notifications (user_id, type, actor_id, post_id, created_at) VALUES (?, ?, ?, ?, ?)')
        .bind(postOwner.user_id, 'echo', user.id, postId, now).run();
    }
    return json({ success: true });
  }

  // Explore (global posts with hotness sorting)
  if (method === 'GET' && path === '/explore') {
    const url = new URL(request.url);
    const limit = parseInt(url.searchParams.get('limit') || '20');
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const now = Math.floor(Date.now() / 1000);
    const posts = await db.prepare(`
      SELECT p.*, u.name, u.avatar_url, u.is_verified,
        (p.like_count + p.comment_count + p.echo_count * 2) / (($now - p.created_at) / 3600 + 1) as hotness
      FROM posts p
      JOIN users u ON p.user_id = u.id
      WHERE u.is_banned = 0
      ORDER BY hotness DESC
      LIMIT ? OFFSET ?
    `).bind(limit, offset).all();
    return json({ posts: posts.results });
  }

  // Search
  if (method === 'GET' && path === '/search') {
    const url = new URL(request.url);
    const q = url.searchParams.get('q') || '';
    if (!q) return json({ posts: [], users: [] });
    const posts = await db.prepare(`
      SELECT p.*, u.name, u.avatar_url, u.is_verified 
      FROM posts p JOIN users u ON p.user_id = u.id 
      WHERE p.content LIKE ? ORDER BY p.created_at DESC LIMIT 20
    `).bind(`%${q}%`).all();
    const users = await db.prepare(`
      SELECT id, name, avatar_url, is_verified FROM users 
      WHERE name LIKE ? OR email LIKE ? LIMIT 10
    `).bind(`%${q}%`, `%${q}%`).all();
    return json({ posts: posts.results, users: users.results });
  }

  // Notifications
  if (method === 'GET' && path === '/notifications') {
    const notifs = await db.prepare(`
      SELECT n.*, u.name as actor_name, u.avatar_url as actor_avatar
      FROM notifications n
      LEFT JOIN users u ON n.actor_id = u.id
      WHERE n.user_id = ?
      ORDER BY n.created_at DESC LIMIT 50
    `).bind(user.id).all();
    return json({ notifications: notifs.results });
  }

  if (method === 'POST' && path === '/notifications/read') {
    await db.prepare('UPDATE notifications SET read = 1 WHERE user_id = ?').bind(user.id).run();
    return json({ success: true });
  }

  // Whispers
  if (method === 'GET' && path === '/whispers/inbox') {
    const whispers = await db.prepare(`
      SELECT id, content, answer, created_at FROM whispers 
      WHERE recipient_id = ? AND expires_at > ? ORDER BY created_at DESC
    `).bind(user.id, Math.floor(Date.now() / 1000)).all();
    return json({ whispers: whispers.results });
  }

  if (method === 'POST' && path === '/whispers') {
    const { recipient_id, content } = body;
    if (!recipient_id || !content) return err('Missing fields');
    const recipient = await db.prepare('SELECT id FROM users WHERE id = ?').bind(recipient_id).first();
    if (!recipient) return err('User not found', 404);
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + 7 * 86400;
    await db.prepare('INSERT INTO whispers (recipient_id, content, created_at, expires_at) VALUES (?, ?, ?, ?)')
      .bind(recipient_id, content, now, expiresAt).run();
    return json({ success: true });
  }

  if (method === 'POST' && path.match(/^\/whispers\/(\d+)\/answer$/)) {
    const whisperId = parseInt(path.split('/')[2]);
    const { answer } = body;
    const whisper = await db.prepare('SELECT recipient_id FROM whispers WHERE id = ?').bind(whisperId).first();
    if (!whisper || whisper.recipient_id !== user.id) return err('Forbidden', 403);
    await db.prepare('UPDATE whispers SET answer = ? WHERE id = ?').bind(answer, whisperId).run();
    return json({ success: true });
  }

  return err('Not found', 404);
}

async function handleAdmin(method, path, body, db, user) {
  if (!user || user.role !== 'admin') return err('Forbidden', 403);

  // List users
  if (method === 'GET' && path === '/admin/users') {
    const users = await db.prepare('SELECT id, email, name, role, is_approved, is_banned, is_verified FROM users').all();
    return json({ users: users.results });
  }

  // Approve user
  if (method === 'POST' && path === '/admin/user/approve') {
    const { userId } = body;
    await db.prepare('UPDATE users SET is_approved = 1 WHERE id = ?').bind(userId).run();
    return json({ success: true });
  }

  // Ban user
  if (method === 'POST' && path === '/admin/user/ban') {
    const { userId } = body;
    await db.prepare('UPDATE users SET is_banned = 1, is_approved = 0 WHERE id = ?').bind(userId).run();
    await db.prepare('DELETE FROM posts WHERE user_id = ?').bind(userId).run();
    return json({ success: true });
  }

  // Unban user
  if (method === 'POST' && path === '/admin/user/unban') {
    const { userId } = body;
    await db.prepare('UPDATE users SET is_banned = 0 WHERE id = ?').bind(userId).run();
    return json({ success: true });
  }

  // Verify user (verified badge)
  if (method === 'POST' && path === '/admin/user/verify') {
    const { userId, verified } = body;
    await db.prepare('UPDATE users SET is_verified = ? WHERE id = ?').bind(verified ? 1 : 0, userId).run();
    return json({ success: true });
  }

  // Delete any post
  if (method === 'DELETE' && path.match(/^\/admin\/post\/(\d+)$/)) {
    const postId = parseInt(path.split('/').pop());
    await db.prepare('DELETE FROM posts WHERE id = ?').bind(postId).run();
    return json({ success: true });
  }

  // Banned words management
  if (method === 'GET' && path === '/admin/banned-words') {
    const words = await db.prepare('SELECT word, language FROM banned_words').all();
    return json({ words: words.results });
  }

  if (method === 'POST' && path === '/admin/banned-words') {
    const { word } = body;
    if (!word) return err('Word required');
    await db.prepare('INSERT OR IGNORE INTO banned_words (word, language) VALUES (?, ?)').bind(word.toLowerCase(), 'admin').run();
    cachedBadWords = null;
    return json({ success: true });
  }

  if (method === 'DELETE' && path === '/admin/banned-words') {
    const { word } = body;
    await db.prepare('DELETE FROM banned_words WHERE word = ?').bind(word.toLowerCase()).run();
    cachedBadWords = null;
    return json({ success: true });
  }

  // Settings (ImgBB API key)
  if (method === 'GET' && path === '/admin/settings') {
    const apiKey = await db.prepare('SELECT value FROM settings WHERE key = "imgbb_api_key"').first();
    return json({ imgbb_api_key: apiKey?.value || '' });
  }

  if (method === 'POST' && path === '/admin/settings') {
    const { imgbb_api_key } = body;
    await db.prepare('UPDATE settings SET value = ? WHERE key = "imgbb_api_key"').bind(imgbb_api_key).run();
    return json({ success: true });
  }

  // Stats
  if (method === 'GET' && path === '/admin/stats') {
    const userCount = await db.prepare('SELECT COUNT(*) as count FROM users').first();
    const postCount = await db.prepare('SELECT COUNT(*) as count FROM posts').first();
    const pendingApprovals = await db.prepare('SELECT COUNT(*) as count FROM users WHERE is_approved = 0 AND role = "user"').first();
    return json({ users: userCount.count, posts: postCount.count, pendingApprovals: pendingApprovals.count });
  }

  // Manual cleanup
  if (method === 'POST' && path === '/admin/cleanup') {
    await runPruning(db);
    return json({ success: true });
  }

  return err('Not found', 404);
}

// ---------- main handler ----------
export async function onRequest(context) {
  const { request, env } = context;
  const db = env.REVERB_DB;

  if (request.method === 'OPTIONS') {
    return new Response(null, { 
      status: 204, 
      headers: { 
        'Access-Control-Allow-Origin': '*', 
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', 
        'Access-Control-Allow-Headers': 'Content-Type,Authorization' 
      } 
    });
  }

  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api/, '');
  const method = request.method;
  let body = {};
  if (method !== 'GET' && method !== 'DELETE') {
    try { body = await request.json(); } catch(e) {}
  }

  // Initialize tables once
  if (!globalThis.__tablesReady) {
    await ensureTables(db);
    globalThis.__tablesReady = true;
  }

  // Auth routes
  if (path.startsWith('/auth/')) {
    const res = await handleAuth(method, path, body, db);
    if (res) return res;
  }

  // Protected routes
  const user = await getUser(request, db);
  if (!user && !path.startsWith('/auth/')) {
    return err('Unauthorized', 401);
  }

  // User routes
  const userRes = await handleUser(method, path, body, db, user, request);
  if (userRes) return userRes;

  // Admin routes
  const adminRes = await handleAdmin(method, path, body, db, user);
  if (adminRes) return adminRes;

  return err('Not found', 404);
}
