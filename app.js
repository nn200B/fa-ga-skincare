const express = require('express');
// Load environment variables (e.g., PayPal credentials)
try { require('dotenv').config(); } catch (e) {}
const mysql = require('mysql2');
const session = require('express-session');
const flash = require('connect-flash');
const multer = require('multer');
const app = express();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const axios = require('axios');
const netsService = require('./services/nets');

// Improve observability: catch top-level errors and log them so we can see why the process exits.
process.on('uncaughtException', (err) => {
    console.error('UNCAUGHT EXCEPTION:', err && err.stack ? err.stack : String(err));
    try { fs.appendFileSync(path.join(__dirname, 'data', 'server-error.log'), `UNCAUGHT: ${new Date().toISOString()}\n${String(err)}\n${err && err.stack ? err.stack + '\n' : ''}\n`); } catch(e){}
    // don't exit immediately - allow logs to flush
});
process.on('unhandledRejection', (reason) => {
    console.error('UNHANDLED REJECTION:', reason);
    try { fs.appendFileSync(path.join(__dirname, 'data', 'server-error.log'), `UNHANDLED_REJECTION: ${new Date().toISOString()}\n${String(reason)}\n\n`); } catch(e){}
});

console.log('Starting GlowAura Skincare App (pid=' + process.pid + ')');

// ---------------- PayPal configuration ----------------
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || '';
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || '';
const PAYPAL_ENV = (process.env.PAYPAL_ENVIRONMENT || process.env.PAYPAL_ENV || 'SANDBOX').toLowerCase();
let PAYPAL_API_BASE = process.env.PAYPAL_API || ((PAYPAL_ENV === 'live' || PAYPAL_ENV === 'production')
    ? 'https://api-m.paypal.com'
    : 'https://api-m.sandbox.paypal.com');
// Normalize legacy base URLs to the modern api-m endpoints
try {
    if (/api\.sandbox\.paypal\.com/i.test(PAYPAL_API_BASE)) PAYPAL_API_BASE = 'https://api-m.sandbox.paypal.com';
    if (/api\.paypal\.com$/i.test(PAYPAL_API_BASE)) PAYPAL_API_BASE = 'https://api-m.paypal.com';
} catch (e) {}
const PAYPAL_CURRENCY = process.env.PAYPAL_CURRENCY || 'SGD';

// Set up multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images'); // Directory to save uploaded files
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname); 
    }
});

const upload = multer({ storage: storage });

let connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Republic_C207',
    database: 'c372_glowaura_skincare'
});
// If SKIP_DB is enabled we will later overwrite connection with a safe stub to avoid accidental DB calls crashing the app.

// Keep SKIP_DB flag for products/carts, but orders will ignore it and use JSON store
const SKIP_DB = String(process.env.SKIP_DB || '').toLowerCase() === 'true';
if (!SKIP_DB) {
    connection.connect((err) => {
            if (err) {
                    console.error('Error connecting to MySQL:', err);
                    return;
            }
            console.log('Connected to MySQL database');

            // Ensure carts table exists (stores JSON cart per user)
            const createCartsTable = `
                CREATE TABLE IF NOT EXISTS carts (
                    userId INT PRIMARY KEY,
                    cartData TEXT
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            `;
            connection.query(createCartsTable, (err) => {
                if (err) console.error('Failed to ensure carts table:', err);
            });
            // Ensure categories table exists for admin-managed categories
            const createCategoriesTable = `
                CREATE TABLE IF NOT EXISTS categories (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(64) NOT NULL UNIQUE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            `;
            connection.query(createCategoriesTable, (err) => {
                if (err) console.error('Failed to ensure categories table:', err);
            });

            // Ensure 2FA columns exist on users table (ignore errors if they already exist)
            const addTwoFaColumns = `
                ALTER TABLE users
                ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(64) NULL,
                ADD COLUMN IF NOT EXISTS twofa_enabled TINYINT(1) NOT NULL DEFAULT 0;
            `;
            connection.query(addTwoFaColumns, (err) => {
                if (err) {
                    // Fallback for MySQL versions without IF NOT EXISTS
                    connection.query('ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64) NULL', () => {});
                    connection.query('ALTER TABLE users ADD COLUMN twofa_enabled TINYINT(1) NOT NULL DEFAULT 0', () => {});
                }
            });
    });
} else {
    console.log('SKIP_DB=true -> skipping MySQL connection and using in-memory storage');
}
// In-memory fallback data (used when SKIP_DB=true)
const inMemory = {
    categories: [
        { id: 1, name: 'Cleansers' },
        { id: 2, name: 'Serums' },
        { id: 3, name: 'Moisturizers' },
        { id: 4, name: 'Sun Care' },
        { id: 5, name: 'Eye Care' },
        { id: 6, name: 'Masks' }
    ],
    products: [
        { id: 1, productName: 'Velvet Cloud Cream Cleanser', quantity: 80, price: 29.00, image: 'cleanser_velvet_cloud.png', category: 'Cleansers' },
        { id: 2, productName: 'Green Tea Gel Cleanser', quantity: 100, price: 24.00, image: 'cleanser_green_tea.png', category: 'Cleansers' },
        { id: 3, productName: 'Radiance Vitamin C Serum 15%', quantity: 60, price: 69.00, image: 'serum_vitc_15.png', category: 'Serums' },
        { id: 4, productName: 'Midnight Repair Retinol Serum', quantity: 45, price: 79.00, image: 'serum_retinol_midnight.png', category: 'Serums' },
        { id: 5, productName: 'HydraSilk Daily Moisturizer', quantity: 90, price: 58.00, image: 'moist_hydrasilk.png', category: 'Moisturizers' },
        { id: 6, productName: 'Ceramide Barrier Cream Rich', quantity: 40, price: 72.00, image: 'moist_ceramide_rich.png', category: 'Moisturizers' },
        { id: 7, productName: 'Weightless SPF50 Fluid', quantity: 120, price: 45.00, image: 'suncare_spf50_fluid.png', category: 'Sun Care' },
        { id: 8, productName: 'Tinted Mineral SPF40', quantity: 70, price: 52.00, image: 'suncare_tinted_spf40.png', category: 'Sun Care' },
        { id: 9, productName: 'Peptide Eye Renewal Cream', quantity: 55, price: 68.00, image: 'eye_peptide_renewal.png', category: 'Eye Care' },
        { id: 10, productName: '24K Gold Illuminating Eye Masks (6 pairs)', quantity: 35, price: 54.00, image: 'eye_gold_masks.png', category: 'Eye Care' },
        { id: 11, productName: 'Rose Quartz Overnight Sleeping Mask', quantity: 50, price: 64.00, image: 'mask_rose_quartz.png', category: 'Masks' },
        { id: 12, productName: 'Pore-Refining Clay Detox Mask', quantity: 65, price: 39.00, image: 'mask_clay_detox.png', category: 'Masks' }
    ],
    nextProductId: 13,
    nextCategoryId: 7,
    orders: [],
    nextOrderId: 1,
    notifications: [],
    nextNotificationId: 1,
    refundRequests: [],
    nextRefundId: 1,
    addressChangeRequests: [],
    nextAddressChangeId: 1,
    users: [],
    nextUserId: 1
};

// JSON-backed dev store (persist in SKIP_DB mode)
const STORE_DIR = path.join(__dirname, 'data');
const STORE_PATH = path.join(STORE_DIR, 'store.json');

function persistStore(cb) {
    try {
        if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
        fs.writeFile(STORE_PATH, JSON.stringify(inMemory, null, 2), 'utf8', (err) => {
            if (err) console.error('Failed to persist store.json:', err);
            if (typeof cb === 'function') cb(err);
        });
    } catch (e) {
        console.error('persistStore error:', e);
        if (typeof cb === 'function') cb(e);
    }
}

function loadStore() {
    try {
        if (fs.existsSync(STORE_PATH)) {
            const raw = fs.readFileSync(STORE_PATH, 'utf8');
            const parsed = JSON.parse(raw || '{}');
            if (parsed && typeof parsed === 'object') {
                inMemory.categories = parsed.categories || inMemory.categories;
                inMemory.products = parsed.products || inMemory.products;
                inMemory.nextProductId = parsed.nextProductId || inMemory.nextProductId;
                inMemory.nextCategoryId = parsed.nextCategoryId || inMemory.nextCategoryId;
                    inMemory.orders = parsed.orders || inMemory.orders;
                    inMemory.nextOrderId = parsed.nextOrderId || inMemory.nextOrderId;
                    inMemory.notifications = parsed.notifications || inMemory.notifications;
                    inMemory.nextNotificationId = parsed.nextNotificationId || inMemory.nextNotificationId;
                    inMemory.refundRequests = parsed.refundRequests || inMemory.refundRequests;
                    inMemory.nextRefundId = parsed.nextRefundId || inMemory.nextRefundId;
                    inMemory.addressChangeRequests = parsed.addressChangeRequests || inMemory.addressChangeRequests;
                    inMemory.nextAddressChangeId = parsed.nextAddressChangeId || inMemory.nextAddressChangeId;
            }
        } else {
            // create store file from defaults
            persistStore(() => {});
        }
    } catch (e) {
        console.error('Failed to load store.json, using defaults:', e);
    }
}

// Load store on startup when SKIP_DB (call after loadStore is defined and inMemory exists)
if (SKIP_DB) loadStore();

// If SKIP_DB is enabled, replace the MySQL connection with a safe stub that won't throw
if (SKIP_DB) {
    connection = {
        query: function(sql, params, cb) {
            // normalize arguments
            if (typeof params === 'function') { cb = params; params = []; }
            // Very small heuristic: if the SQL starts with SELECT return empty array; otherwise return an OK-like object
            const s = (sql || '').toString().trim().toUpperCase();
            if (s.startsWith('SELECT')) return cb && cb(null, []);
            // mimic result object for inserts/updates
            return cb && cb(null, { insertId: 0, affectedRows: 0 });
        }
    };
}

// Helper abstraction so routes can use DB or in-memory fallback
function getCategories(cb) {
    if (SKIP_DB) return cb(null, inMemory.categories.slice());
    connection.query('SELECT * FROM categories ORDER BY name', (err, rows) => {
        if (err) return cb(err);
        return cb(null, rows || []);
    });
}

function addCategory(name, cb) {
    if (!name) return cb(new Error('Missing name'));
    if (SKIP_DB) {
        // avoid duplicates by name
        const existing = inMemory.categories.find(c => c.name.toLowerCase() === name.toLowerCase());
        if (existing) return cb(null, existing);
        const c = { id: inMemory.nextCategoryId++, name };
        inMemory.categories.push(c);
        // persist change
        persistStore(() => cb(null, c));
    }
    connection.query('INSERT IGNORE INTO categories (name) VALUES (?)', [name], (err, result) => {
        if (err) return cb(err);
        // fetch the inserted/existing row
        connection.query('SELECT * FROM categories WHERE name = ?', [name], (sErr, rows) => {
            if (sErr) return cb(sErr);
            return cb(null, rows && rows[0]);
        });
    });
}

function deleteCategoryById(id, cb) {
    if (!id) return cb(new Error('Missing id'));
    if (SKIP_DB) {
        const idx = inMemory.categories.findIndex(c => String(c.id) === String(id));
        if (idx === -1) return cb(null, { affectedRows: 0 });
        inMemory.categories.splice(idx,1);
        // persist change
        persistStore(() => cb(null, { affectedRows: 1 }));
    }
    connection.query('DELETE FROM categories WHERE id = ?', [id], (err, result) => {
        if (err) return cb(err);
        return cb(null, result);
    });
}

function getProducts(filter, cb) {
    // filter: { category }
    if (SKIP_DB) {
        let items = inMemory.products.slice();
        if (filter && filter.category) {
            items = items.filter(p => (p.category || '').toLowerCase() === String(filter.category).toLowerCase());
        }
        return cb(null, items);
    }
    let sql = 'SELECT * FROM products';
    const params = [];
    if (filter && filter.category) {
        sql += ' WHERE category = ?';
        params.push(filter.category);
    }
    connection.query(sql, params, (err, rows) => {
        if (err) return cb(err);
        return cb(null, rows || []);
    });
}

function addOrder(order, cb) {
    // Simple in-memory / JSON-backed implementation for orders only
    const o = Object.assign({}, order);
    if (!inMemory.nextOrderId) inMemory.nextOrderId = 1;
    if (!Array.isArray(inMemory.orders)) inMemory.orders = [];

    o.id = inMemory.nextOrderId++;
    o.createdAt = new Date().toISOString();
    o.status = o.status || 'paid';
    o.deliveryStatus = o.deliveryStatus || 'processing';

    inMemory.orders.push(o);

    persistStore(() => {
        if (cb) cb(null, o);
    });
}

// ---------------- Membership & Points Helpers ----------------

// Tier thresholds (Option A)
const MEMBERSHIP_TIERS = [
    { name: 'Bronze', min: 0, max: 499 },
    { name: 'Silver', min: 500, max: 1499 },
    { name: 'Gold', min: 1500, max: 2999 },
    { name: 'Platinum', min: 3000, max: Infinity }
];

const POINTS_PER_DOLLAR = 1;
const REDEEM_POINTS_FREE_DELIVERY = 300;

function calculateTier(points) {
    const p = Number(points) || 0;
    for (let i = 0; i < MEMBERSHIP_TIERS.length; i++) {
        const t = MEMBERSHIP_TIERS[i];
        if (p >= t.min && p <= t.max) return t;
    }
    return MEMBERSHIP_TIERS[0];
}

function buildMembershipSummary(user) {
    const points = user && typeof user.points !== 'undefined' ? Number(user.points) || 0 : 0;
    const tier = calculateTier(points);
    const idx = MEMBERSHIP_TIERS.findIndex(t => t.name === tier.name);
    const next = idx >= 0 && idx < MEMBERSHIP_TIERS.length - 1 ? MEMBERSHIP_TIERS[idx + 1] : null;
    const currentMax = tier.max === Infinity ? null : tier.max;
    const nextTierPoints = next ? next.min : null;
    const pointsToNext = next ? Math.max(0, next.min - points) : 0;
    let progressPercent = 100;
    if (next && currentMax) {
        const range = next.min - tier.min;
        const within = Math.min(points, next.min) - tier.min;
        progressPercent = Math.max(0, Math.min(100, Math.round((within / range) * 100)));
    }
    return {
        points,
        tierName: tier.name,
        nextTierName: next ? next.name : null,
        nextTierPoints,
        pointsToNext,
        currentTierMax: currentMax,
        progressPercent,
        redeemCostFreeDelivery: REDEEM_POINTS_FREE_DELIVERY
    };
}

function getOrdersByUser(userId, cb) {
    const list = (inMemory.orders || []).filter(o => String(o.userId) === String(userId)).slice().reverse();
    if (cb) cb(null, list);
}

function getAllOrders(cb) {
    const list = (inMemory.orders || []).slice().reverse();
    if (cb) cb(null, list);
}

// Helpers for refund and address change requests (JSON-backed only)
function addRefundRequest(data, cb) {
    const r = {
        id: inMemory.nextRefundId++,
        userId: data.userId,
        username: data.username,
        orderId: data.orderId,
        reason: data.reason,
        status: 'pending',
        createdAt: new Date().toISOString()
    };
    inMemory.refundRequests.push(r);
    persistStore(() => cb && cb(null, r));
}

function updateRefundStatus(id, status, cb) {
    const r = (inMemory.refundRequests || []).find(x => String(x.id) === String(id));
    if (!r) return cb && cb(new Error('Refund not found'));
    r.status = status;
    if (status === 'approved') {
        r.refundStatus = 'refund accepted';
    } else if (status === 'processing') {
        r.refundStatus = 'processing refund';
    } else if (status === 'completed') {
        r.refundStatus = 'refund completed';
    } else if (status === 'rejected') {
        r.refundStatus = 'refund rejected';
    }
    r.updatedAt = new Date().toISOString();
    persistStore(() => cb && cb(null, r));
}

function getRefunds(cb) {
    const list = (inMemory.refundRequests || []).slice().reverse();
    if (cb) cb(null, list);
}

function addAddressChangeRequest(data, cb) {
    const r = {
        id: inMemory.nextAddressChangeId++,
        userId: data.userId,
        username: data.username,
        orderId: data.orderId,
        newAddress: data.newAddress,
        reason: data.reason,
        status: 'submitted',
        createdAt: new Date().toISOString()
    };
    inMemory.addressChangeRequests.push(r);
    persistStore(() => cb && cb(null, r));
}

function getAddressChangeRequests(cb) {
    const list = (inMemory.addressChangeRequests || []).slice().reverse();
    if (cb) cb(null, list);
}

function updateAddressChangeStatus(id, status, cb) {
    const r = (inMemory.addressChangeRequests || []).find(x => String(x.id) === String(id));
    if (!r) return cb && cb(new Error('Address change not found'));
    r.status = status;
    r.updatedAt = new Date().toISOString();
    persistStore(() => cb && cb(null, r));
}

// Notifications
function addNotification(data, cb) {
    const n = {
        id: inMemory.nextNotificationId++,
        userId: data.userId || null, // null or 0 for admin/global notifications
        role: data.role || null,     // 'admin' or 'user' (optional)
        type: data.type || 'info',   // e.g. 'order', 'refund', 'address', etc.
        message: data.message || '',
        link: data.link || null,
        createdAt: new Date().toISOString(),
        read: false
    };
    inMemory.notifications.push(n);
    persistStore(() => cb && cb(null, n));
}

function getNotificationsForUser(user, cb) {
    const uid = getUserIdFromSessionUser(user);
    const role = user && user.role;
    const list = (inMemory.notifications || []).filter(n => {
        // Admin notifications: role === 'admin'
        if (role === 'admin') {
            return n.role === 'admin';
        }
        // User notifications: match userId or global user notifications
        return n.role === 'user' && (n.userId == null || String(n.userId) === String(uid));
    }).slice().reverse();
    if (cb) cb(null, list);
}

function markNotificationRead(id, cb) {
    const n = (inMemory.notifications || []).find(x => String(x.id) === String(id));
    if (!n) return cb && cb(new Error('Notification not found'));
    n.read = true;
    n.readAt = new Date().toISOString();
    persistStore(() => cb && cb(null, n));
}

function markNotificationUnread(id, cb) {
    const n = (inMemory.notifications || []).find(x => String(x.id) === String(id));
    if (!n) return cb && cb(new Error('Notification not found'));
    n.read = false;
    delete n.readAt;
    persistStore(() => cb && cb(null, n));
}

function updateOrderStatus(orderId, newStatus, cb) {
    const o = (inMemory.orders || []).find(x => String(x.id) === String(orderId));
    if (!o) {
        if (cb) cb(new Error('Order not found'));
        return;
    }
    o.deliveryStatus = newStatus;
    if (!o.history) o.history = [];
    o.history.push({ status: newStatus, at: new Date().toISOString() });
    persistStore(() => {
        if (cb) cb(null, o);
    });
}

// Helper to get the current logged-in user id from session user
function getUserIdFromSessionUser(user) {
    if (!user) return null;
    if (user.id) return user.id;
    if (user.userId) return user.userId;
    return null;
}

function addProduct(data, cb) {
    // data: { productName, quantity, price, image, category }
    if (SKIP_DB) {
        const p = {
            id: inMemory.nextProductId++,
            productName: data.productName || 'Unnamed',
            quantity: Number(data.quantity) || 0,
            price: Number(data.price) || 0,
            image: data.image || null,
            category: data.category || null
        };
        inMemory.products.push(p);
        // persist change
        persistStore(() => cb(null, p));
    }
    const sql = 'INSERT INTO products (productName, quantity, price, image, category) VALUES (?, ?, ?, ?, ?)';
    connection.query(sql, [data.productName, data.quantity, data.price, data.image, data.category], (err, result) => {
        if (err) return cb(err);
        // fetch inserted row
        connection.query('SELECT * FROM products WHERE id = ?', [result.insertId], (sErr, rows) => {
            if (sErr) return cb(sErr);
            return cb(null, rows && rows[0]);
        });
    });
}

function getProductById(id, cb) {
    if (SKIP_DB) {
        const p = inMemory.products.find(x => String(x.id) === String(id));
        return cb(null, p ? [p] : []);
    }
    connection.query('SELECT * FROM products WHERE id = ?', [id], (err, rows) => {
        if (err) return cb(err);
        return cb(null, rows || []);
    });
}

// Set up view engine
app.set('view engine', 'ejs');
//  enable static files
app.use(express.static('public'));
// enable form processing
app.use(express.urlencoded({
    extended: false
}));

// make sure JSON body parsing is enabled for future endpoints
app.use(express.json());

//TO DO: Insert code for Session Middleware below 
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
    // Session expires after 1 week of inactivity
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } 
}));

app.use(flash());

// Quick test-login route (always available) placed early so it's reachable even if other routing changes happen.
app.get('/_quick_login', (req, res) => {
    // Create an admin session quickly for testing without DB.
    req.session.user = { id: 1, username: 'dev_admin', role: 'admin' };
    req.session.cart = [];
    // Small confirmation page with a link to inventory
    res.send('<html><body><p>Test admin session created. <a href="/inventory">Go to inventory</a></p></body></html>');
});

// expose cart count to all views via res.locals
app.use((req, res, next) => {
    try {
        const cart = req.session && Array.isArray(req.session.cart) ? req.session.cart : [];
        // total quantity
        const count = cart.reduce((s, i) => s + (Number(i.quantity) || 0), 0);
        res.locals.cartCount = count;
    } catch (e) {
        res.locals.cartCount = 0;
    }
    // Expose unread/new orders count for admin badge
    try {
        if (req.session && req.session.user && req.session.user.role === 'admin') {
            res.locals.newOrdersCount = (inMemory.orders || []).filter(o => o.new).length;
            // Admin notification badge
            res.locals.notificationCount = (inMemory.notifications || []).filter(n => n.role === 'admin' && !n.read).length;
        } else {
            res.locals.newOrdersCount = 0;
            // User notification badge
            const uid = getUserIdFromSessionUser(req.session && req.session.user);
            res.locals.notificationCount = (inMemory.notifications || []).filter(n => n.role === 'user' && !n.read && (n.userId == null || String(n.userId) === String(uid))).length;
        }
    } catch (e) { res.locals.newOrdersCount = 0; }
    next();
});

// Prevent caching of authenticated pages so browser 'back' won't show stale protected pages
app.use((req, res, next) => {
    try {
        // Only set no-cache for HTML responses and when a user was/has been logged in for the session
        // This reduces impact on static assets while protecting sensitive pages from being shown after logout.
        const acceptsHtml = (req.get('Accept') || '').includes('text/html') || req.accepts('html');
        // Apply no-cache headers for HTML responses so browsers will re-request
        // the page when using Back/Forward, ensuring the server can enforce
        // authentication/redirects after logout.
        if (acceptsHtml) {
            res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.set('Pragma', 'no-cache');
            res.set('Expires', '0');
            res.set('Surrogate-Control', 'no-store');
        }
    } catch (e) {
        // noop
    }
    next();
});

// Middleware to check if user is logged in
const checkAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next();
    } else {
        // If this is an AJAX/fetch request, return JSON 401 instead of redirecting HTML
        const acceptsJson = req.xhr || (req.get('Accept') || '').includes('application/json') || req.get('content-type') === 'application/json';
        if (acceptsJson) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        req.flash('error', 'Please log in to view this resource');
        return res.redirect('/login');
    }
};

// Middleware to check if user is admin
const checkAdmin = (req, res, next) => {
    if (req.session.user.role === 'admin') {
        return next();
    } else {
        req.flash('error', 'Access denied');
        res.redirect('/shopping');
    }
};

// Middleware to block admin users from user-only features (cart)
const checkNotAdmin = (req, res, next) => {
    if (req.session && req.session.user && req.session.user.role === 'admin') {
        // If the client expects JSON (AJAX/fetch), return 403 JSON. Otherwise redirect for normal browsers.
        const acceptsJson = req.xhr || (req.get('Accept') || '').includes('application/json') || req.get('content-type') === 'application/json';
        if (acceptsJson) {
            return res.status(403).json({ error: 'Admins do not use the cart.' });
        }
        req.flash('error', 'Admins do not use the cart.');
        return res.redirect('/inventory');
    }
    return next();
};

    // Membership page route (requires auth, user-only)
    app.get('/membership', checkAuthenticated, checkNotAdmin, (req, res) => {
        const membership = buildMembershipSummary(req.session.user || {});
        res.render('membership', { user: req.session.user, membership });
    });

// Helper: load full user row by id
function getUserById(id, cb){
    if (!id) return cb(new Error('Missing user id'));
    connection.query('SELECT * FROM users WHERE id = ?', [id], (err, rows) => {
        if (err) return cb(err);
        cb(null, rows && rows[0]);
    });
}

// Helper: get all users (for admin user management)
function getAllUsers(cb){
    connection.query('SELECT id, username, email, role, points, contact FROM users ORDER BY id ASC', (err, rows) => {
        if (err) return cb(err);
        const list = (rows || []).map(r => {
            const u = Object.assign({}, r);
            u.membership = buildMembershipSummary({ points: u.points || 0 });
            return u;
        });
        cb(null, list);
    });
}

// Helper: update basic profile fields
function updateUserProfile(id, data, cb){
    const { username, email, address, contact } = data;
    connection.query(
        'UPDATE users SET username = ?, email = ?, address = ?, contact = ? WHERE id = ?',
        [username, email, address, contact, id],
        (err, result) => cb(err, result)
    );
}

// Helper: update password using SHA1 like existing code
function updateUserPassword(id, newPassword, cb){
    connection.query(
        'UPDATE users SET password = SHA1(?) WHERE id = ?',
        [newPassword, id],
        (err, result) => cb(err, result)
    );
}

// Middleware for form validation
const validateRegistration = (req, res, next) => {
    const { username, email, password, address, contact, role } = req.body;

    if (!username || !email || !password || !address || !contact || !role) {
        return res.status(400).send('All fields are required.');
    }
    
    if (password.length < 6) {
        req.flash('error', 'Password should be at least 6 or more characters long');
        req.flash('formData', req.body);
        return res.redirect('/register');
    }
    next();
};

// Define routes
app.get('/',  (req, res) => {
    res.render('index', {user: req.session.user} );
});

app.get('/inventory', checkAuthenticated, checkAdmin, (req, res) => {
        // Fetch products and categories (DB or in-memory)
        getProducts({}, (pErr, products) => {
            if (pErr) {
                console.error('Failed to load products for inventory:', pErr);
                return res.status(500).send('Database error');
            }
            getCategories((cErr, cats) => {
                const categories = (cErr || !cats) ? [] : (cats.map ? cats.map(r => r.name || r) : cats);
                res.render('inventory', { products: products, user: req.session.user, categories });
            });
        });
});

// Admin user management
app.get('/admin/users', checkAuthenticated, checkAdmin, (req, res) => {
    getAllUsers((err, users) => {
        if (err) {
            console.error('Failed to load users for admin:', err);
            req.flash('error', 'Could not load users.');
            return res.redirect('/inventory');
        }
        const errors = req.flash('error');
        const success = req.flash('success');
        res.render('admin_users', { user: req.session.user, users: users || [], errors, success });
    });
});

// Admin update user (role, contact). Admin cannot change their own role.
app.post('/admin/users/:id/update', checkAuthenticated, checkAdmin, (req, res) => {
    const targetId = req.params.id;
    const { role, contact } = req.body || {};
    const selfId = getUserIdFromSessionUser(req.session.user);
    if (!targetId) {
        req.flash('error', 'Missing user id.');
        return res.redirect('/admin/users');
    }
    // Validate role if provided
    const newRole = (role || '').trim();
    if (newRole && newRole !== 'admin' && newRole !== 'user') {
        req.flash('error', 'Invalid role.');
        return res.redirect('/admin/users');
    }

    // Prevent changing own role
    if (newRole && String(targetId) === String(selfId)) {
        req.flash('error', 'You cannot change your own role.');
        return res.redirect('/admin/users');
    }

    // Build dynamic update
    const fields = [];
    const params = [];
    if (newRole) {
        fields.push('role = ?');
        params.push(newRole);
    }
    if (typeof contact !== 'undefined') {
        fields.push('contact = ?');
        params.push(contact);
    }
    if (!fields.length) {
        req.flash('error', 'No changes to update.');
        return res.redirect('/admin/users');
    }
    params.push(targetId);
    const sql = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;
    connection.query(sql, params, (err) => {
        if (err) {
            console.error('Failed to update user:', err);
            req.flash('error', 'Could not update user.');
        } else {
            req.flash('success', 'User updated.');
        }
        return res.redirect('/admin/users');
    });
});

app.post('/admin/users/:id/delete', checkAuthenticated, checkAdmin, (req, res) => {
    const id = req.params.id;
    if (!id) {
        req.flash('error', 'Missing user id.');
        return res.redirect('/admin/users');
    }
    // prevent deleting admins
    connection.query('SELECT role FROM users WHERE id = ?', [id], (err, rows) => {
        if (err) {
            console.error('Failed to check user role before delete:', err);
            req.flash('error', 'Could not delete user.');
            return res.redirect('/admin/users');
        }
        const row = rows && rows[0];
        if (!row) {
            req.flash('error', 'User not found.');
            return res.redirect('/admin/users');
        }
        if (row.role === 'admin') {
            req.flash('error', 'Cannot delete admin accounts.');
            return res.redirect('/admin/users');
        }
        connection.query('DELETE FROM users WHERE id = ?', [id], (delErr) => {
            if (delErr) {
                console.error('Failed to delete user:', delErr);
                req.flash('error', 'Could not delete user.');
            } else {
                req.flash('success', 'User deleted.');
            }
            return res.redirect('/admin/users');
        });
    });
});

app.get('/register', (req, res) => {
    res.render('register', { messages: req.flash('error'), formData: req.flash('formData')[0] });
});

app.post('/register', validateRegistration, (req, res) => {

    const { username, email, password, address, contact, role } = req.body;

    const sql = 'INSERT INTO users (username, email, password, address, contact, role) VALUES (?, ?, SHA1(?), ?, ?, ?)';
    connection.query(sql, [username, email, password, address, contact, role], (err, result) => {
        if (err) {
            console.error('DB error during registration:', err);
            req.flash('error', 'Registration failed. Try a different email or contact admin.');
            return res.redirect('/register');
        }
        const newUserId = result.insertId;
        // Generate TOTP secret and store
        const secret = speakeasy.generateSecret({ length: 20, name: `GlowAura (${username})` });
        const otpauthUrl = secret.otpauth_url;
        connection.query('UPDATE users SET totp_secret = ?, twofa_enabled = 1 WHERE id = ?', [secret.base32, newUserId], (uErr) => {
            if (uErr) console.error('Failed to store 2FA secret:', uErr);
            // Store setup info in session and redirect to setup page to show QR
            req.session.totpSetup = { userId: newUserId, otpauthUrl };
            return res.redirect('/setup-2fa');
        });
    });
});

app.get('/login', (req, res) => {
    res.render('login', { messages: req.flash('success'), errors: req.flash('error') });
});
// Show QR for 2FA setup after registration
app.get('/setup-2fa', (req, res) => {
    const setup = req.session.totpSetup;
    if (!setup || !setup.otpauthUrl) {
        return res.render('setup_2fa', { error: 'No 2FA setup data found.', qrDataUrl: null, secretBase32: null });
    }
    QRCode.toDataURL(setup.otpauthUrl, { errorCorrectionLevel: 'M' }, (err, url) => {
        if (err) {
            return res.render('setup_2fa', { error: 'Failed to generate QR code.', qrDataUrl: null, secretBase32: null });
        }
        // Retrieve secret for display from DB
        connection.query('SELECT totp_secret FROM users WHERE id = ?', [setup.userId], (e, rows) => {
            const base32 = rows && rows[0] && rows[0].totp_secret ? rows[0].totp_secret : null;
            res.render('setup_2fa', { error: null, qrDataUrl: url, secretBase32: base32 });
        });
    });
});

app.post('/login', (req, res) => {
    const { email, password, totp } = req.body;

    // Validate email and password
    if (!email || !password) {
        req.flash('error', 'All fields are required.');
        return res.redirect('/login');
    }

    const sql = 'SELECT * FROM users WHERE email = ? AND password = SHA1(?)';
    connection.query(sql, [email, password], (err, results) => {
        if (err) {
            console.error('DB error during login:', err);
            req.flash('error', 'Login failed due to server error.');
            return res.redirect('/login');
        }

        if (results.length > 0) {
            const dbUser = results[0];
            if (dbUser.twofa_enabled) {
                const isValid = speakeasy.totp.verify({ secret: dbUser.totp_secret, encoding: 'base32', token: (totp || '').trim(), window: 1 });
                if (!isValid) {
                    req.flash('error', 'Invalid or missing 2FA code.');
                    return res.redirect('/login');
                }
            }
            // Successful login
            req.session.user = dbUser;

            // load persisted cart for this user
            const uid = getUserIdFromSessionUser(req.session.user);
            loadCartFromDB(uid, (err, savedCart) => {
              if (err) console.error('Failed to load saved cart:', err);
              // If session already has cart items (e.g., guest added items), merge them with savedCart:
              const sessionCart = req.session.cart || [];
              if (sessionCart.length === 0) {
                req.session.cart = savedCart || [];
              } else {
                // merge: keep quantities summed by productId
                const map = {};
                (savedCart || []).forEach(i => { map[String(i.productId || i.id)] = { ...i }; });
                sessionCart.forEach(i => {
                  const key = String(i.productId || i.id);
                  if (map[key]) {
                    map[key].quantity = (map[key].quantity || 0) + (i.quantity || 0);
                  } else {
                    map[key] = { ...i };
                  }
                });
                req.session.cart = Object.values(map).filter(item => item.productId && item.quantity > 0);  // Filter invalid items
              }

              // persist merged session cart back to DB
              const finalUid = uid;
              saveCartToDB(finalUid, req.session.cart, (saveErr) => {
                if (saveErr) console.error('Failed to save merged cart:', saveErr);
                req.flash('success', 'Login successful!');
                if(req.session.user.role == 'user')
                    res.redirect('/shopping');
                else
                    res.redirect('/inventory');
              });
            });
        } else {
            // Invalid credentials
            req.flash('error', 'Invalid email or password.');
            res.redirect('/login');
        }
    });
});

// Profile page (both user and admin)
app.get('/profile', checkAuthenticated, (req, res) => {
    const sessionUser = req.session.user;
    getUserById(sessionUser.id, (err, dbUser) => {
        if (err || !dbUser) {
            console.error('Failed to load profile user:', err);
            req.flash('error', 'Could not load profile.');
            return res.redirect('/');
        }
        const formData = {
            username: dbUser.username,
            email: dbUser.email,
            address: dbUser.address,
            contact: dbUser.contact
        };
        res.render('profile', {
            user: dbUser,
            messages: req.flash('success'),
            errors: req.flash('error'),
            formData,
            passwordStep: req.session.passwordStep || 'start',
            otpHint: req.session.passwordOtpHint || null
        });
    });
});

// Update profile details
app.post('/profile', checkAuthenticated, (req, res) => {
    const uid = getUserIdFromSessionUser(req.session.user);
    const { username, email, address, contact } = req.body;
    if (!username || !email) {
        req.flash('error', 'Name and email are required.');
        return res.redirect('/profile');
    }
    updateUserProfile(uid, { username, email, address, contact }, (err) => {
        if (err) {
            console.error('Failed to update profile:', err);
            req.flash('error', 'Could not update profile.');
            return res.redirect('/profile');
        }
        // keep session in sync for navbar greeting etc.
        if (req.session.user) {
            req.session.user.username = username;
            req.session.user.email = email;
            req.session.user.address = address;
            req.session.user.contact = contact;
        }
        req.flash('success', 'Profile updated successfully.');
        res.redirect('/profile');
    });
});

// Step 1: request OTP for password change
app.post('/profile/password/request-otp', checkAuthenticated, (req, res) => {
    const uid = getUserIdFromSessionUser(req.session.user);
    const { currentPassword, newPassword, newPassword2 } = req.body;
    if (!currentPassword || !newPassword || !newPassword2) {
        req.flash('error', 'Please fill in all password fields.');
        return res.redirect('/profile');
    }
    if (newPassword !== newPassword2) {
        req.flash('error', 'New passwords do not match.');
        return res.redirect('/profile');
    }
    if (newPassword.length < 6) {
        req.flash('error', 'New password should be at least 6 characters.');
        return res.redirect('/profile');
    }
    // verify current password
    connection.query('SELECT * FROM users WHERE id = ? AND password = SHA1(?)', [uid, currentPassword], (err, rows) => {
        if (err) {
            console.error('Error verifying current password:', err);
            req.flash('error', 'Could not verify current password.');
            return res.redirect('/profile');
        }
        if (!rows || rows.length === 0) {
            req.flash('error', 'Current password is incorrect.');
            return res.redirect('/profile');
        }
        // generate OTP and store in session with short expiry
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        req.session.passwordOtp = otp;
        req.session.passwordOtpExpires = Date.now() + 5 * 60 * 1000; // 5 minutes
        req.session.passwordNew = newPassword;
        req.session.passwordStep = 'otp';
        // For this assignment, show OTP on screen as a hint (simulated SMS/email)
        req.session.passwordOtpHint = otp;
        req.flash('success', 'We have generated a one-time code. Enter it below to confirm your new password.');
        res.redirect('/profile');
    });
});

// Step 2: confirm OTP and change password
app.post('/profile/password/confirm', checkAuthenticated, (req, res) => {
    const uid = getUserIdFromSessionUser(req.session.user);
    const { otp } = req.body;
    const storedOtp = req.session.passwordOtp;
    const expiresAt = req.session.passwordOtpExpires;
    const newPassword = req.session.passwordNew;

    if (!storedOtp || !expiresAt || !newPassword) {
        req.flash('error', 'No active password change request. Please try again.');
        return res.redirect('/profile');
    }
    if (Date.now() > expiresAt) {
        req.flash('error', 'The one-time code has expired. Please start again.');
        req.session.passwordOtp = null;
        req.session.passwordOtpExpires = null;
        req.session.passwordNew = null;
        req.session.passwordStep = 'start';
        req.session.passwordOtpHint = null;
        return res.redirect('/profile');
    }
    if (!otp || otp.trim() !== String(storedOtp)) {
        req.flash('error', 'The one-time code is incorrect.');
        return res.redirect('/profile');
    }

    updateUserPassword(uid, newPassword, (err) => {
        if (err) {
            console.error('Failed to update password:', err);
            req.flash('error', 'Could not update password.');
            return res.redirect('/profile');
        }
        // clear sensitive session fields
        req.session.passwordOtp = null;
        req.session.passwordOtpExpires = null;
        req.session.passwordNew = null;
        req.session.passwordStep = 'start';
        req.session.passwordOtpHint = null;
        req.flash('success', 'Your password has been updated.');
        res.redirect('/profile');
    });
});

// Simple server-side pagination for shopping page
const SHOP_PAGE_SIZE = 6; // products per page

app.get('/shopping', checkAuthenticated, checkNotAdmin, (req, res) => {
    // Optional category filtering from query string.
    const rawCategory = (req.query.category || '').trim();
    const category = (rawCategory && String(rawCategory).toLowerCase() !== 'all') ? rawCategory : '';

    // Page number (1-based)
    let page = parseInt(req.query.page || '1', 10);
    if (isNaN(page) || page < 1) page = 1;

    // Load categories and products (DB or in-memory)
    getCategories((cErr, cats) => {
        const categories = (cErr || !cats) ? [] : (cats.map ? cats.map(r => r.name || r) : cats);
        getProducts({ category }, (pErr, products) => {
            if (pErr) {
                console.error('Failed to load products for shopping:', pErr);
                return res.status(500).send('Database error');
            }

            const totalItems = products.length;
            const totalPages = Math.max(Math.ceil(totalItems / SHOP_PAGE_SIZE) || 1, 1);
            const currentPage = Math.min(page, totalPages);
            const startIdx = (currentPage - 1) * SHOP_PAGE_SIZE;
            const endIdx = startIdx + SHOP_PAGE_SIZE;
            const pageProducts = products.slice(startIdx, endIdx);

            res.render('shopping', {
                user: req.session.user,
                products: pageProducts,
                category: category,
                categories,
                page: currentPage,
                totalPages,
                totalItems
            });
        });
    });
});

// Allow guests to add to cart (no login required). Admins are still blocked.
app.post('/add-to-cart/:id', checkNotAdmin, (req, res) => {
    const productId = parseInt(req.params.id);
    const quantity = parseInt(req.body.quantity) || 1;

    // Debug logging to help trace AJAX failures
    try {
        const acceptsJson = req.xhr || (req.get('Accept') || '').includes('application/json') || req.get('content-type') === 'application/json';
        console.log('DEBUG POST /add-to-cart called', { productId, acceptsJson, cookiePresent: !!req.headers.cookie, sessionUser: getUserIdFromSessionUser(req.session && req.session.user) });
    } catch (e) {
        console.log('DEBUG POST /add-to-cart logging failed', e && e.message);
    }
    connection.query('SELECT * FROM products WHERE id = ?', [productId], (error, results) => {
        if (error) {
            console.error('DB error fetching product by id:', error);
            return res.status(500).send('Database error');
        }

        if (results.length > 0) {
            const product = results[0];

            // Ensure session cart exists
            if (!req.session.cart) {
                req.session.cart = [];
            }

            // Current quantity in cart for this product
            const existingItem = req.session.cart.find(item => item.productId === productId);
            const currentQty = existingItem ? (parseInt(existingItem.quantity) || 0) : 0;
            const requestedTotal = currentQty + quantity;

            // If requested quantity exceeds available stock, block and inform user
            if (requestedTotal > product.quantity) {
                const acceptsJson = req.xhr || (req.get('Accept') || '').includes('application/json') || req.get('content-type') === 'application/json';
                const message = `Not enough stock available. Only ${product.quantity} left.`;
                if (acceptsJson) {
                    return res.status(400).json({ success: false, error: message, available: product.quantity, inCart: currentQty });
                }
                req.flash('error', message);
                return res.redirect('/shopping');
            }

            // Otherwise, add/update item in cart
            if (existingItem) {
                existingItem.quantity = requestedTotal;
            } else {
                req.session.cart.push({
                    productId: productId,
                    productName: product.productName,
                    price: product.price,
                    quantity: quantity,
                    image: product.image
                });
            }

                        // save session cart to DB for logged-in user
                        const uid = getUserIdFromSessionUser(req.session.user);
                        const acceptsJson = req.xhr || (req.get('Accept') || '').includes('application/json') || req.get('content-type') === 'application/json';
                        const afterSave = () => {
                            const cartQuantity = (req.session.cart || []).reduce((s, it) => s + (Number(it.quantity) || 0), 0);
                            if (acceptsJson) {
                                return res.json({ success: true, cartLength: req.session.cart.length, cartQuantity });
                            }
                            // For normal form posts, stay on the current page instead of redirecting to /cart.
                            // Redirect back to the referrer (usually /shopping or product page); fallback to /shopping.
                            const referer = req.get('referer') || '/shopping';
                            return res.redirect(referer);
                        };

                        if (uid) {
                            saveCartToDB(uid, req.session.cart, (err) => {
                                if (err) console.error('Failed to save cart after add:', err);
                                return afterSave();
                            });
                        } else {
                            return afterSave();
                        }
        } else {
            res.status(404).send("Product not found");
        }
    });
});

app.get('/cart', checkAuthenticated, checkNotAdmin, (req, res) => {
    const cart = req.session.cart || [];
    res.render('cart', { cart, user: req.session.user });
});

// Update quantity for a cart item
app.post('/cart/update', checkAuthenticated, checkNotAdmin, (req, res) => {
    const pid = req.body.productId || req.body.pid;
    let qty = parseInt(req.body.quantity, 10);
    if (!pid || isNaN(qty)) {
        req.flash('error', 'Invalid quantity update.');
        return res.redirect('/cart');
    }
    if (qty < 1) qty = 1;

    if (!Array.isArray(req.session.cart)) req.session.cart = [];
    const item = req.session.cart.find(it => String(it.productId) === String(pid));
    if (!item) {
        req.flash('error', 'Item not found in cart.');
        return res.redirect('/cart');
    }

    item.quantity = qty;

    // persist updated cart to DB for logged-in user
    const uid = getUserIdFromSessionUser(req.session.user);
    const finish = () => {
        req.flash('success', 'Cart updated.');
        res.redirect('/cart');
    };
    if (uid) {
        saveCartToDB(uid, req.session.cart, (err) => {
            if (err) console.error('Failed to save cart after quantity update:', err);
            finish();
        });
    } else {
        finish();
    }
});

// Handle selection of items from cart for checkout
app.post('/cart/selection', checkAuthenticated, checkNotAdmin, (req, res) => {
    const cart = req.session.cart || [];
    let selected = req.body.selected || [];
    if (!Array.isArray(selected)) selected = [selected];
    const selectedIds = new Set(selected.map(x => String(x)));

    const filtered = cart.filter(it => selectedIds.has(String(it.productId)));
    if (!filtered.length) {
        req.flash('error', 'Please select item(s) to check out.');
        return res.redirect('/cart');
    }

    // Store selected items in session for checkout flow
    req.session.selectedCartItems = filtered;
    return res.redirect('/delivery-details');
});

// Clear entire shopping cart
app.post('/cart/clear', checkAuthenticated, checkNotAdmin, (req, res) => {
    req.session.cart = [];
    req.session.selectedCartItems = [];
    const uid = getUserIdFromSessionUser(req.session.user);
    if (uid) {
        saveCartToDB(uid, req.session.cart, (err) => {
            if (err) console.error('Failed to save cart on clear:', err);
            req.flash('success', 'Cart cleared.');
            return res.redirect('/cart');
        });
    } else {
        req.flash('success', 'Cart cleared.');
        return res.redirect('/cart');
    }
});

// Helper to remove item and persist cart
function removeItemAndSave(req, res, productId) {
    if (!req.session.cart || !Array.isArray(req.session.cart)) req.session.cart = [];
    req.session.cart = req.session.cart.filter(item => String(item.productId) !== String(productId));
    const uid = getUserIdFromSessionUser(req.session.user);
    if (uid) {
        saveCartToDB(uid, req.session.cart, (err) => {
            if (err) console.error('Failed to save cart after delete:', err);
            return res.redirect('/cart');
        });
    } else {
        return res.redirect('/cart');
    }
}

// POST via form body: /cart/delete
app.post('/cart/delete', checkAuthenticated, checkNotAdmin, (req, res) => {
    const productId = req.body.productId || req.body.pid;
    if (!productId) {
        console.warn('No productId provided in body, redirecting to /cart');
        return res.redirect('/cart');
    }
    removeItemAndSave(req, res, productId);
});

// POST via URL param: /cart/delete/:productId
app.post('/cart/delete/:productId', checkAuthenticated, checkNotAdmin, (req, res) => {
    const productId = req.params.productId;
    if (!productId) return res.redirect('/cart');
    removeItemAndSave(req, res, productId);
});

app.get('/logout', (req, res) => {
    // save cart for logged in user before destroying session
    const uid = req.session ? getUserIdFromSessionUser(req.session.user) : null;
    const cartToSave = (req.session && req.session.cart) ? req.session.cart : [];
    if (uid) {
      saveCartToDB(uid, cartToSave, (err) => {
        if (err) console.error('Failed to save cart on logout:', err);
                // Destroy session and clear cookie, redirect to login
                req.session.destroy((destroyErr) => {
                    try { res.clearCookie('connect.sid'); } catch(e){}
                    return res.redirect('/login');
                });
      });
    } else {
            req.session.destroy((destroyErr) => {
                try { res.clearCookie('connect.sid'); } catch(e){}
                return res.redirect('/login');
            });
    }
});

app.get('/product/:id', checkAuthenticated, (req, res) => {
  // Extract the product ID from the request parameters
  const productId = req.params.id;

  // Fetch data from MySQL based on the product ID
  connection.query('SELECT * FROM products WHERE id = ?', [productId], (error, results) => {
      if (error) {
          console.error('DB error fetching product by id:', error);
          return res.status(500).send('Database error');
      }

      // Check if any product with the given ID was found
      if (results.length > 0) {
          // Render HTML page with the product data
          res.render('product', { product: results[0], user: req.session.user  });
      } else {
          // If no product with the given ID was found, render a 404 page or handle it accordingly
          res.status(404).send('Product not found');
      }
  });
});

app.get('/addProduct', checkAuthenticated, checkAdmin, (req, res) => {
    // fetch categories for select dropdown (DB or in-memory)
    getCategories((err, rows) => {
        const categories = (err || !rows) ? [] : (rows.map ? rows.map(r => r.name || r) : rows);
        res.render('addProduct', { user: req.session.user, categories });
    });
});

app.post('/addProduct', checkAuthenticated, checkAdmin, upload.single('image'),  (req, res) => {  // Fixed: Added missing auth middleware
    // Extract product data from the request body
    let { name, quantity, price, category, newCategory } = req.body;
    // If admin provided a newCategory, ensure it's present
    const ensureCategoryThenAddProduct = (cb) => {
        if (newCategory && newCategory.trim()) {
            const newName = newCategory.trim();
            addCategory(newName, (err, row) => {
                if (err) console.error('Failed to insert new category:', err);
                category = newName;
                return cb();
            });
        } else {
            return cb();
        }
    };

    let image = null;
    if (req.file) image = req.file.filename;

    ensureCategoryThenAddProduct(() => {
        // Use helper addProduct which handles DB or in-memory
        addProduct({ productName: name, quantity: quantity, price: price, image: image, category: category }, (err, created) => {
            if (err) {
                console.error('Error adding product:', err);
                return res.status(500).send('Error adding product');
            }
            return res.redirect('/inventory');
        });
    });
});

app.get('/updateProduct/:id',checkAuthenticated, checkAdmin, (req,res) => {
    const productId = req.params.id;
    const sql = 'SELECT * FROM products WHERE id = ?';
    // Fetch data from DB or in-memory
    getProductById(productId, (err, results) => {
        if (err) {
            console.error('DB error fetching product for update:', err);
            return res.status(500).send('Database error');
        }
        if (!results || results.length === 0) return res.status(404).send('Product not found');
        getCategories((cErr, rows) => {
            const categories = (cErr || !rows) ? [] : (rows.map ? rows.map(r => r.name || r) : rows);
            res.render('updateProduct', { product: results[0], user: req.session.user, categories });
        });
    });
});

app.post('/updateProduct/:id', checkAuthenticated, checkAdmin, upload.single('image'), (req, res) => {  // Fixed: Added missing auth middleware
        const productId = req.params.id;
        // Extract product data from the request body
        let { name, quantity, price, category, newCategory } = req.body;
        // If admin provided a newCategory, insert it into categories table (ignore errors)
        if (newCategory && newCategory.trim()) {
            const newName = newCategory.trim();
            addCategory(newName, (err) => {
                if (err) console.error('Failed to insert new category:', err);
            });
            category = newName;
        }
        let image  = req.body.currentImage; //retrieve current image filename
        if (req.file) { //if new image is uploaded
                image = req.file.filename; // set image to be new image filename
        }

        // If running with SKIP_DB, update in-memory product
        if (SKIP_DB) {
            const prod = inMemory.products.find(p => String(p.id) === String(productId));
            if (!prod) return res.status(404).send('Product not found');
            prod.productName = name;
            prod.quantity = Number(quantity) || prod.quantity;
            prod.price = Number(price) || prod.price;
            prod.image = image || prod.image;
            prod.category = category || prod.category;
            // persist change then redirect
            return persistStore(() => res.redirect('/inventory'));
        }

        const updateWithCategory = () => {
            const sql = 'UPDATE products SET productName = ? , quantity = ?, price = ?, image = ?, category = ? WHERE id = ?';
            connection.query(sql, [name, quantity, price, image, category || null, productId], updateCallback);
        };

        const updateWithoutCategory = () => {
            const sql = 'UPDATE products SET productName = ? , quantity = ?, price = ?, image = ? WHERE id = ?';
            connection.query(sql, [name, quantity, price, image, productId], updateCallback);
        };

        const updateCallback = (error, results) => {
            if (error) {
                console.error('Error updating product:', error);
                if (error.code === 'ER_BAD_FIELD_ERROR') {
                    console.log('Category column missing; retrying update without category');
                    return updateWithoutCategory();
                }
                return res.status(500).send('Error updating product');
            }
            return res.redirect('/inventory');
        };

        if (typeof category !== 'undefined') {
            updateWithCategory();
        } else {
            updateWithoutCategory();
        }
});

// Categories routes
// User view: /categories_user (read-only, just to select category and shop)
app.get('/categories_user', checkAuthenticated, (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        return res.redirect('/admin/categories');
    }
    getCategories((err, rows) => {
        if (err) {
            console.error('Failed to load categories:', err);
            return res.status(500).send('Failed to load categories');
        }
        const categories = rows || [];
        return res.render('categories_user', { categories, user: req.session.user });
    });
});

// Admin view: list categories with products under each
app.get('/admin/categories', checkAuthenticated, checkAdmin, (req, res) => {
    getCategories((cErr, catRows) => {
        if (cErr) {
            console.error('Failed to load categories for admin:', cErr);
            req.flash('error', 'Could not load categories');
            return res.redirect('/inventory');
        }
        const categories = catRows || [];
        // load all products once, then group by category name
        getProducts({}, (pErr, products) => {
            if (pErr) {
                console.error('Failed to load products for admin categories:', pErr);
                req.flash('error', 'Could not load products');
                return res.redirect('/inventory');
            }
            const grouped = categories.map(c => {
                const items = (products || []).filter(p => (p.category || '') === c.name);
                return { category: c, products: items };
            });
            res.render('categories', { user: req.session.user, groupedCategories: grouped });
        });
    });
});

// Admin-only category add/delete (users cannot change categories)
app.post('/admin/categories', checkAuthenticated, checkAdmin, (req, res) => {
    const name = (req.body.name || '').trim();
    if (!name) {
        req.flash('error', 'Category name is required');
        return res.redirect('/admin/categories');
    }
    addCategory(name, (err) => {
        if (err) {
            console.error('Failed to add category:', err);
            req.flash('error', 'Could not add category');
        } else {
            req.flash('success', 'Category added');
        }
        return res.redirect('/admin/categories');
    });
});

app.post('/admin/categories/:id/delete', checkAuthenticated, checkAdmin, (req, res) => {
    const id = req.params.id;
    deleteCategoryById(id, (err) => {
        if (err) {
            console.error('Failed to delete category:', err);
            req.flash('error', 'Could not delete category');
        } else {
            req.flash('success', 'Category deleted');
        }
        return res.redirect('/admin/categories');
    });
});

// NOTE: Inline quantity update via AJAX removed — quantities are edited via the product Edit form now.

// Admin view of help center requests
app.get('/admin/help-center', checkAuthenticated, checkAdmin, (req, res) => {
    getRefunds((rErr, refunds) => {
        if (rErr) {
            console.error('Failed to load refunds:', rErr);
        }
        getAddressChangeRequests((aErr, addressChanges) => {
            if (aErr) {
                console.error('Failed to load address changes:', aErr);
            }
            res.render('admin_help_center', {
                user: req.session.user,
                refunds: refunds || [],
                addressChanges: addressChanges || [],
                errors: req.flash('error'),
                success: req.flash('success')
            });
        });
    });
});

// Admin takes decision on refund: approve or reject
app.post('/admin/help-center/refund/:id/decision', checkAuthenticated, checkAdmin, async (req, res) => {
    const refundId = req.params.id;
    const decision = (req.body.decision || '').toLowerCase();
    if (decision !== 'approve' && decision !== 'reject') {
        req.flash('error', 'Invalid decision.');
        return res.redirect('/admin/help-center');
    }
    const newStatus = decision === 'approve' ? 'approved' : 'rejected';
    
    try {
        const r = (inMemory.refundRequests || []).find(x => String(x.id) === String(refundId));
        if (!r) {
            req.flash('error', 'Refund request not found.');
            return res.redirect('/admin/help-center');
        }

        // When approved, process PayPal refund if payment was via PayPal
        if (newStatus === 'approved') {
            const order = (inMemory.orders || []).find(o => String(o.id) === String(r.orderId));
            
            if (order) {
                // Check if payment was made via PayPal or Stripe
                const paymentMethod = order.paymentMethod || (order.paymentDetails && order.paymentDetails.method);
                const paypalOrderId = order.paymentDetails && order.paymentDetails.paypalOrderId;
                const stripePaymentIntentId = order.paymentDetails && order.paymentDetails.stripePaymentIntentId;
                
                if (paymentMethod === 'paypal' && paypalOrderId) {
                    try {
                        console.log('Processing PayPal refund for order:', paypalOrderId);
                        
                        // First, get the capture ID from the PayPal order
                        const accessToken = await paypalGetAccessToken();
                        const orderDetailsUrl = PAYPAL_API_BASE + '/v2/checkout/orders/' + encodeURIComponent(paypalOrderId);
                        const { status: orderStatus, data: orderData } = await httpRequestJson(orderDetailsUrl, {
                            method: 'GET',
                            headers: {
                                'Authorization': 'Bearer ' + accessToken,
                                'Content-Type': 'application/json'
                            }
                        });

                        if (orderStatus >= 200 && orderStatus < 300 && orderData) {
                            // Extract capture ID from the order details
                            const captureId = orderData.purchase_units && 
                                            orderData.purchase_units[0] && 
                                            orderData.purchase_units[0].payments && 
                                            orderData.purchase_units[0].payments.captures && 
                                            orderData.purchase_units[0].payments.captures[0] && 
                                            orderData.purchase_units[0].payments.captures[0].id;

                            if (captureId) {
                                // Process the refund with PayPal (full refund)
                                const refundAmount = order.total ? String(Number(order.total).toFixed(2)) : null;
                                const refundData = await paypalRefundCaptureRemote(
                                    captureId, 
                                    refundAmount, 
                                    PAYPAL_CURRENCY
                                );
                                
                                console.log('PayPal refund processed successfully:', refundData);
                                
                                // Store refund details in the request
                                r.paypalRefundId = refundData.id;
                                r.paypalRefundStatus = refundData.status;
                                r.refundedAmount = refundAmount;
                                
                                req.flash('success', `Refund approved and processed via PayPal. Refund ID: ${refundData.id}`);
                            } else {
                                console.warn('Could not find capture ID for PayPal order:', paypalOrderId);
                                req.flash('warning', 'Refund approved locally, but PayPal capture ID not found. Please process refund manually in PayPal dashboard.');
                            }
                        } else {
                            console.warn('Failed to get PayPal order details:', orderStatus, orderData);
                            req.flash('warning', 'Refund approved locally, but could not retrieve PayPal order details. Please process refund manually.');
                        }
                    } catch (paypalError) {
                        console.error('PayPal refund error:', paypalError);
                        req.flash('error', `Refund approved locally, but PayPal refund failed: ${paypalError.message}. Please process manually in PayPal dashboard.`);
                        r.paypalRefundError = paypalError.message;
                    }
                } else if (paymentMethod === 'stripe' && stripePaymentIntentId) {
                    try {
                        console.log('Processing Stripe refund for payment intent:', stripePaymentIntentId);
                        
                        // Process the refund with Stripe (full refund)
                        const refundAmount = order.total ? Number(order.total) : null;
                        const refundData = await stripeRefundPaymentIntent(stripePaymentIntentId, refundAmount);
                        
                        console.log('Stripe refund processed successfully:', refundData);
                        
                        // Store refund details in the request
                        r.stripeRefundId = refundData.id;
                        r.stripeRefundStatus = refundData.status;
                        r.refundedAmount = refundAmount ? refundAmount.toFixed(2) : order.total;
                        
                        req.flash('success', `Refund approved and processed via Stripe. Refund ID: ${refundData.id}`);
                    } catch (stripeError) {
                        console.error('Stripe refund error:', stripeError);
                        req.flash('error', `Refund approved locally, but Stripe refund failed: ${stripeError.message}. Please process manually in Stripe dashboard.`);
                        r.stripeRefundError = stripeError.message;
                    }
                } else {
                    // Non-PayPal/Stripe order (QR/NETS) - just mark as refunded locally
                    req.flash('success', `Refund accepted for order #${r.orderId}. (Non-PayPal/Stripe payment - process refund manually if needed)`);
                }

                // Remove order from active orders list
                const idx = (inMemory.orders || []).findIndex(o => String(o.id) === String(r.orderId));
                if (idx !== -1) {
                    inMemory.orders.splice(idx, 1);
                }

                // Add history to refund request
                if (!r.history) r.history = [];
                r.history.push({ 
                    status: 'order cancelled and refund accepted', 
                    at: new Date().toISOString() 
                });
            }

            // Update refund status
            updateRefundStatus(refundId, newStatus, (err) => {
                if (err) {
                    console.error('Failed to update refund status:', err);
                }
                persistStore(() => {});
            });

            // Notify user about refund decision
            addNotification({
                role: 'user',
                userId: r.userId,
                type: 'refund',
                message: `Your order #${r.orderId} has been cancelled and refund accepted.`,
                link: '/notifications'
            });
        } else {
            // Rejected
            updateRefundStatus(refundId, newStatus, (err) => {
                if (err) {
                    console.error('Failed to update refund status:', err);
                }
            });
            
            req.flash('success', `Refund request #${refundId} rejected.`);
            
            // Notify user about refund rejection
            addNotification({
                role: 'user',
                userId: r.userId,
                type: 'refund',
                message: `Your refund request for order #${r.orderId} has been rejected.`,
                link: '/orders'
            });
        }
    } catch (err) {
        console.error('Error processing refund decision:', err);
        req.flash('error', 'An error occurred while processing the refund decision.');
    }
    
    return res.redirect('/admin/help-center');
});

// Admin takes decision on address change: approve or reject
app.post('/admin/help-center/address-change/:id/decision', checkAuthenticated, checkAdmin, (req, res) => {
    const id = req.params.id;
    const decision = (req.body.decision || '').toLowerCase();

    if (!id || (decision !== 'approve' && decision !== 'reject')) {
        req.flash('error', 'Invalid decision for address change request.');
        return res.redirect('/admin/help-center');
    }

    getAddressChangeRequests((err, list) => {
        if (err) {
            console.error('Failed to load address change requests:', err);
            req.flash('error', 'Could not process address change request.');
            return res.redirect('/admin/help-center');
        }
        const reqItem = (list || []).find(r => String(r.id) === String(id));
        if (!reqItem) {
            req.flash('error', 'Address change request not found.');
            return res.redirect('/admin/help-center');
        }

        const newStatus = decision === 'approve' ? 'approved' : 'rejected';

        // If approved, also update the order's delivery address in the JSON store
        if (decision === 'approve') {
            const order = (inMemory.orders || []).find(o => String(o.id) === String(reqItem.orderId));
            if (order) {
                order.deliveryAddress = reqItem.newAddress;
                if (!order.history) order.history = [];
                order.history.push({ status: 'address updated', at: new Date().toISOString() });
            }
        }

        updateAddressChangeStatus(id, newStatus, (e) => {
            if (e) {
                console.error('Failed to update address change status:', e);
                req.flash('error', 'Could not update address change status.');
            } else {
                req.flash('success', `Address change request ${newStatus}.`);
                // Notify user about address change decision
                addNotification({
                    role: 'user',
                    userId: reqItem.userId,
                    type: 'address',
                    message: `Your address change request for order #${reqItem.orderId} has been ${newStatus}.`,
                    link: '/orders/' + encodeURIComponent(reqItem.orderId)
                });
            }
            persistStore(() => {
                return res.redirect('/admin/help-center');
            });
        });
    });
});

// Notifications center for both user and admin
app.get('/notifications', checkAuthenticated, (req, res) => {
    const filter = (req.query.filter || 'all').toLowerCase(); // 'all' | 'unread' | 'read'
    getNotificationsForUser(req.session.user, (err, list) => {
        if (err) {
            console.error('Failed to load notifications:', err);
            req.flash('error', 'Could not load notifications');
            return res.redirect('/');
        }
        const allList = list || [];
        let filtered = allList;
        if (filter === 'unread') {
            filtered = allList.filter(n => !n.read);
        } else if (filter === 'read') {
            filtered = allList.filter(n => n.read);
        }
        res.render('notifications', {
            user: req.session.user,
            notifications: filtered,
            filter,
            totalUnread: allList.filter(n => !n.read).length,
            errors: req.flash('error'),
            success: req.flash('success')
        });
    });
});

// Toggle notification read/unread state
app.post('/notifications/:id/read', checkAuthenticated, (req, res) => {
    markNotificationRead(req.params.id, (err) => {
        if (err) console.error('Failed to mark notification read:', err);
        const redirectTo = req.get('Referer') || '/notifications';
        res.redirect(redirectTo);
    });
});

app.post('/notifications/:id/unread', checkAuthenticated, (req, res) => {
    markNotificationUnread(req.params.id, (err) => {
        if (err) console.error('Failed to mark notification unread:', err);
        const redirectTo = req.get('Referer') || '/notifications';
        res.redirect(redirectTo);
    });
});

// Admin sales analytics page: view revenue & orders by month (paid orders only)
app.get('/admin/sales', checkAuthenticated, checkAdmin, (req, res) => {
    const allOrders = (inMemory.orders || []).filter(o => (o.status || '').toLowerCase() === 'paid');

    // Group by YYYY-MM
    const monthlyMap = {};
    allOrders.forEach(o => {
        const date = o.createdAt ? new Date(o.createdAt) : new Date();
        if (isNaN(date.getTime())) return;
        const key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
        if (!monthlyMap[key]) {
            monthlyMap[key] = { key, year: date.getFullYear(), month: date.getMonth() + 1, totalRevenue: 0, orderCount: 0 };
        }
        const amount = Number(o.subtotal || o.total || 0);
        monthlyMap[key].totalRevenue += isNaN(amount) ? 0 : amount;
        monthlyMap[key].orderCount += 1;
    });

    const monthlySummary = Object.values(monthlyMap).sort((a, b) => a.key.localeCompare(b.key));

    // Selected period filter
    // mode: 'all' | 'this-month' | 'last-month' | 'ytd' | 'this-year' | 'custom'
    const mode = (req.query.mode || 'all').trim();
    const monthParam = (req.query.month || '').trim(); // '01'..'12' when mode === 'custom'

    const now = new Date();
    const currentYear = now.getFullYear();
    const currentMonth = now.getMonth() + 1; // 1-12

    let filteredOrders = allOrders;
    let selectedSummary = null;
    let selectedKey = '';
    if (mode === 'this-month') {
        const key = `${currentYear}-${String(currentMonth).padStart(2, '0')}`;
        filteredOrders = allOrders.filter(o => {
            const d = o.createdAt ? new Date(o.createdAt) : new Date();
            if (isNaN(d.getTime())) return false;
            const k = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
            return k === key;
        });
        selectedSummary = monthlyMap[key] || null;
    } else if (mode === 'last-month') {
        let y = currentYear;
        let m = currentMonth - 1;
        if (m === 0) { m = 12; y = currentYear - 1; }
        const key = `${y}-${String(m).padStart(2, '0')}`;
        filteredOrders = allOrders.filter(o => {
            const d = o.createdAt ? new Date(o.createdAt) : new Date();
            if (isNaN(d.getTime())) return false;
            const k = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
            return k === key;
        });
        selectedSummary = monthlyMap[key] || null;
    } else if (mode === 'ytd') {
        filteredOrders = allOrders.filter(o => {
            const d = o.createdAt ? new Date(o.createdAt) : new Date();
            if (isNaN(d.getTime())) return false;
            return d.getFullYear() === currentYear;
        });
        const yKeyPrefix = `${currentYear}-`;
        selectedSummary = Object.values(monthlyMap)
            .filter(m => m.key.startsWith(yKeyPrefix))
            .reduce((acc, m) => {
                if (!acc) acc = { totalRevenue: 0, orderCount: 0 };
                acc.totalRevenue += m.totalRevenue;
                acc.orderCount += m.orderCount;
                return acc;
            }, null);
    } else if (mode === 'this-year') {
        filteredOrders = allOrders.filter(o => {
            const d = o.createdAt ? new Date(o.createdAt) : new Date();
            if (isNaN(d.getTime())) return false;
            return d.getFullYear() === currentYear;
        });
        const yKeyPrefix = `${currentYear}-`;
        selectedSummary = Object.values(monthlyMap)
            .filter(m => m.key.startsWith(yKeyPrefix))
            .reduce((acc, m) => {
                if (!acc) acc = { totalRevenue: 0, orderCount: 0 };
                acc.totalRevenue += m.totalRevenue;
                acc.orderCount += m.orderCount;
                return acc;
            }, null);
    } else if (mode === 'custom' && monthParam) {
        // Use current year + selected month, e.g. 2025-03
        const customKey = `${currentYear}-${monthParam}`;
        filteredOrders = allOrders.filter(o => {
            const d = o.createdAt ? new Date(o.createdAt) : new Date();
            if (isNaN(d.getTime())) return false;
            const k = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
            return k === customKey;
        });
        selectedSummary = monthlyMap[customKey] || null;
        selectedKey = customKey;
    } // else mode === 'all' => keep allOrders and no selectedSummary

    res.render('admin_sales', {
        user: req.session.user,
        monthlySummary,
        orders: filteredOrders,
        selectedMonth: selectedKey,
        selectedSummary,
        mode
    });
});

app.get('/deleteProduct/:id', checkAuthenticated, checkAdmin, (req, res) => {  // Fixed: Added missing auth middleware
    const productId = req.params.id;

    if (SKIP_DB) {
        const idx = inMemory.products.findIndex(p => String(p.id) === String(productId));
        if (idx !== -1) inMemory.products.splice(idx,1);
        // persist change then redirect
        return persistStore(() => res.redirect('/inventory'));
    }

    connection.query('DELETE FROM products WHERE id = ?', [productId], (error, results) => {
        if (error) {
            // Handle any error that occurs during the database operation
            console.error("Error deleting product:", error);
            res.status(500).send('Error deleting product');
        } else {
            // Send a success response
            res.redirect('/inventory');
        }
    });
});

// helper to get numeric user id from session user object
function getUserIdFromSessionUser(user) {
  if (!user) return null;
  return user.id || user.userId || user.ID || null;
}

// Save cart (array) to DB for given userId
// Save cart (array) to DB for given userId
function saveCartToDB(userId, cart, callback) {
    if (!userId) return callback && callback(new Error('Missing userId'));
    const cartJson = JSON.stringify(cart || []);
    if (SKIP_DB) {
        // store in-memory for tests/dev
        saveCartToDB._store = saveCartToDB._store || {};
        saveCartToDB._store[userId] = cartJson;
        return callback && callback(null, { ok: true });
    }
    const sql = 'INSERT INTO carts (userId, cartData) VALUES (?, ?) ON DUPLICATE KEY UPDATE cartData = VALUES(cartData)';
    connection.query(sql, [userId, cartJson], function(err, result) {
        if (err) {
            console.error('Error saving cart to DB:', err);
            return callback && callback(err);
        }
        callback && callback(null, result);
    });
}

// Load cart from DB for given userId
// Load cart from DB for given userId
function loadCartFromDB(userId, callback) {
    if (!userId) return callback && callback(new Error('Missing userId'));
    if (SKIP_DB) {
        const raw = (saveCartToDB._store && saveCartToDB._store[userId]) || '[]';
        try {
            const cart = JSON.parse(raw);
            return callback && callback(null, cart);
        } catch (e) {
            return callback && callback(e);
        }
    }
    const sql = 'SELECT cartData FROM carts WHERE userId = ?';
    connection.query(sql, [userId], function(err, results) {
        if (err) {
            console.error('Error loading cart from DB:', err);
            return callback && callback(err);
        }
        const cart = (results[0] && results[0].cartData) ? JSON.parse(results[0].cartData) : [];
        callback && callback(null, cart);
    });
}

// DELETE cart item via AJAX — updates session and persists cart if helper exists
app.delete('/cart/delete/:productId', checkAuthenticated, checkNotAdmin, (req, res) => {
    const productId = req.params.productId;
    console.log('DEBUG DELETE /cart/delete/:productId called, productId=', productId);
    console.log('DEBUG session.user=', req.session && req.session.user ? getUserIdFromSessionUser(req.session.user) : null);
    if (!req.session.cart || !Array.isArray(req.session.cart)) req.session.cart = [];

    const beforeCount = req.session.cart.length;
    req.session.cart = req.session.cart.filter(item => String(item.productId) !== String(productId));
    const removedCount = beforeCount - req.session.cart.length;
    console.log('DEBUG cart before=', beforeCount, 'after=', req.session.cart.length, 'removed=', removedCount);

    // persist for logged-in user if helpers exist
    try {
        if (typeof getUserIdFromSessionUser === 'function') {
            const uid = getUserIdFromSessionUser(req.session.user);
            if (uid && typeof saveCartToDB === 'function') {
                saveCartToDB(uid, req.session.cart, (err) => {
                    if (err) console.error('Failed to save cart after delete:', err);
                    console.log('DEBUG saved cart to DB for user', uid);
                    return res.json({ success: true, removed: removedCount, cartLength: req.session.cart.length });
                });
                return;
            }
        }
    } catch (e) {
        console.error('Cart persistence helper error:', e);
    }

    return res.json({ success: true, removed: removedCount, cartLength: req.session.cart.length });
});

// Debug endpoint to inspect session and persisted cart for the logged-in user
app.get('/_debug/cart', checkAuthenticated, (req, res) => {
    const uid = getUserIdFromSessionUser(req.session.user);
    loadCartFromDB(uid, (err, persisted) => {
        if (err) return res.status(500).json({ error: 'Failed to load persisted cart', details: String(err) });
        res.json({ session: req.session.cart || [], persisted: persisted || [] });
    });
});

// Development-only helper: create a test login and pre-populate session (always available)
app.post('/_test/login', (req, res) => {
    // create a simple test user and cart in session
    // allow override via form or JSON for quick testing: ?role=admin or { role: 'admin' }
    const role = (req.body && req.body.role) || req.query.role || 'user';
    req.session.user = { id: 1, role: role };
    req.session.cart = [{ productId: '10', productName: 'Sample', price: 1.0, quantity: 2 }];
    // also persist to in-memory store if SKIP_DB
    saveCartToDB(1, req.session.cart, () => {
        res.json({ ok: true, user: req.session.user, cart: req.session.cart });
    });
});
// Convenience GET endpoint for quick testing in a browser
app.get('/_test/login', (req, res) => {
    const role = (req.query && req.query.role) || 'user';
    req.session.user = { id: 1, role: role };
    req.session.cart = [{ productId: '10', productName: 'Sample', price: 1.0, quantity: 2 }];
    saveCartToDB(1, req.session.cart, () => {
        // Redirect admin to inventory, regular users to shopping
        if (role === 'admin') return res.redirect('/inventory');
        return res.redirect('/shopping');
    });
});

// ------------------ Orders / Checkout / Payment routes ------------------

function addBusinessDays(date, days) {
    const d = new Date(date);
    let added = 0;
    while (added < days) {
        d.setDate(d.getDate() + 1);
        const day = d.getDay(); // 0 Sun, 6 Sat
        if (day !== 0 && day !== 6) added++;
    }
    return d;
}

function estimateDeliveryDate(createdAtIso, deliveryOption) {
    try {
        const created = new Date(createdAtIso || new Date().toISOString());
        if (deliveryOption === 'one-day') {
            return addBusinessDays(created, 1).toISOString();
        }
        // normal -> 3 business days
        return addBusinessDays(created, 3).toISOString();
    } catch (e) {
        return new Date().toISOString();
    }
}

// Delivery details page
app.get('/delivery-details', checkAuthenticated, checkNotAdmin, (req, res) => {
    const cart = req.session.cart || [];
    if (!cart || cart.length === 0) {
        req.flash('error', 'Your cart is empty.');
        return res.redirect('/cart');
    }
    const errors = req.flash('error');
    res.render('delivery_details', { user: req.session.user, errors });
});

app.post('/delivery-details', checkAuthenticated, checkNotAdmin, (req, res) => {
    const { fullName, street, unit, postalCode, note } = req.body || {};
    if (!fullName || !street || !postalCode) {
        req.flash('error', 'Please fill in name, street and postal code.');
        return res.redirect('/delivery-details');
    }
    req.session.delivery = { fullName, street, unit, postalCode, note };
    return res.redirect('/checkout');
});

// GET checkout page
app.get('/checkout', checkAuthenticated, checkNotAdmin, (req, res) => {
    const baseCart = req.session.cart || [];
    const cart = Array.isArray(req.session.selectedCartItems) && req.session.selectedCartItems.length
        ? req.session.selectedCartItems
        : baseCart;
    if (!cart || cart.length === 0) {
        req.flash('error', 'Your cart is empty.');
        return res.redirect('/cart');
    }
    if (!req.session.delivery) {
        return res.redirect('/delivery-details');
    }
    const subtotal = cart.reduce((s, it) => s + (Number(it.price || 0) * Number(it.quantity || 0)), 0);
    const errors = req.flash('error');
    const success = req.flash('success');
    const membership = buildMembershipSummary(req.session.user || {});
    res.render('checkout', {
        cart,
        subtotal,
        user: req.session.user,
        errors,
        success,
        delivery: req.session.delivery,
        membership,
        paypalClientId: PAYPAL_CLIENT_ID,
        paypalCurrency: PAYPAL_CURRENCY,
        paypalEnv: PAYPAL_ENV,
        stripePublishableKey: STRIPE_PUBLISHABLE_KEY
    });
});

// POST checkout -> choose delivery & payment
app.post('/checkout', checkAuthenticated, checkNotAdmin, (req, res) => {
    console.log('POST /checkout body:', req.body);
    const { deliveryOption, paymentMethod, usePointsFreeDelivery } = req.body || {};
        const baseCart = req.session.cart || [];
        const cart = Array.isArray(req.session.selectedCartItems) && req.session.selectedCartItems.length
            ? req.session.selectedCartItems
            : baseCart;

        if (!cart || cart.length === 0) {
                req.flash('error', 'Cart is empty');
                return res.redirect('/cart');
        }

        const subtotal = cart.reduce((s, it) => s + (Number(it.price || 0) * Number(it.quantity || 0)), 0);

        const now = new Date();
        const cutoffHour = 13; // 1pm
        let deliveryCost = 10;
        let pointsRedeemed = 0;

        if (deliveryOption === 'one-day') {
                if (now.getHours() >= cutoffHour) {
                        req.flash('error', 'One-day delivery must be ordered before 1pm. Please choose Normal delivery or order earlier.');
                        return res.redirect('/checkout');
                }
                deliveryCost = 25;
        }

            // Membership: allow redeeming points for free normal delivery
            const user = req.session.user || null;
            const membership = buildMembershipSummary(user || {});
            const wantsFreeDelivery = usePointsFreeDelivery === 'on' || usePointsFreeDelivery === '1';
            if (wantsFreeDelivery && deliveryOption === 'normal' && membership.points >= REDEEM_POINTS_FREE_DELIVERY) {
                deliveryCost = 0;
                pointsRedeemed = REDEEM_POINTS_FREE_DELIVERY;
            }

        const total = Number(subtotal) + Number(deliveryCost);

        const orderBase = {
                userId: getUserIdFromSessionUser(req.session.user),
                items: cart.slice(),
                subtotal,
                deliveryOption: deliveryOption || 'normal',
                deliveryCost,
                total,
            paymentMethod: paymentMethod || 'card',
            delivery: req.session.delivery || null
        };

        // QR branch (legacy in-app QR)
        if (paymentMethod === 'qr') {
                const temp = Object.assign({}, orderBase, {
                        status: 'pending_payment',
                        deliveryStatus: 'processing'
                });
                addOrder(temp, (err, created) => {
                        if (err || !created || !created.id) {
                                console.error('Order create warning (QR):', err);
                                req.flash('error', 'Could not create order. Please try again.');
                                return res.redirect('/checkout');
                        }
                        req.session.recentOrderId = created.id;
                        return res.redirect('/pay/qr/' + encodeURIComponent(created.id));
                });
                return;
        }

        // NETS QR branch
        if (paymentMethod === 'nets') {
            const temp = Object.assign({}, orderBase, {
            status: 'pending_payment',
            deliveryStatus: 'processing'
            });
            addOrder(temp, (err, created) => {
            if (err || !created || !created.id) {
                console.error('Order create warning (NETS):', err);
                req.flash('error', 'Could not create order. Please try again.');
                return res.redirect('/checkout');
            }
            // Remember pending order for success confirmation step
            req.session.recentOrderId = created.id;
            req.session.netsPending = true;
            return res.redirect('/pay/nets/' + encodeURIComponent(created.id));
            });
            return;
        }

        // Card branch (default) - always proceed and then redirect
        const cardNumber = (req.body.cardNumber || '').replace(/\s+/g, '');
        const cvv = (req.body.cvv || '').replace(/\s+/g, '');
        const holder = (req.body.cardHolder || '').trim();

        const toCreate = Object.assign({}, orderBase, {
            status: 'paid',
            paymentDetails: {
                method: 'card',
                holder,
                last4: cardNumber.slice(-4),
                cvv
            },
            deliveryStatus: 'processing',
            membership: {
                pointsEarned: Math.floor(subtotal * POINTS_PER_DOLLAR),
                pointsRedeemed: pointsRedeemed
            }
        });

        addOrder(toCreate, (err, created) => {
            if (err || !created || !created.id) {
                console.error('Order create warning (card):', err);
                req.flash('error', 'Order was created with warnings.');
                return res.redirect('/orders');
            }

            // Deduct stock from products for each item in the paid order
            try {
                (created.items || []).forEach(item => {
                    const pid = item.productId || item.id;
                    const qty = Number(item.quantity) || 0;
                    if (!pid || qty <= 0) return;
                    const sql = 'UPDATE products SET quantity = GREATEST(quantity - ?, 0) WHERE id = ?';
                    connection.query(sql, [qty, pid], (e) => {
                        if (e) console.error('Failed to deduct stock for product', pid, e);
                    });
                });
            } catch (e) {
                console.error('Error during stock deduction:', e);
            }

            // clear selected items and/or cart and save
            if (Array.isArray(req.session.selectedCartItems) && req.session.selectedCartItems.length) {
                const selectedIds = new Set(req.session.selectedCartItems.map(it => String(it.productId)));
                req.session.cart = (req.session.cart || []).filter(it => !selectedIds.has(String(it.productId)));
                req.session.selectedCartItems = [];
            } else {
                req.session.cart = [];
            }
            const uid = getUserIdFromSessionUser(req.session.user);
            if (uid) saveCartToDB(uid, req.session.cart, () => {});

            // Award and redeem membership points for paid orders
            try {
                if (user && uid) {
                    const earned = Math.floor(subtotal * POINTS_PER_DOLLAR);
                    let currentPoints = Number(user.points || 0) || 0;
                    currentPoints += earned;
                    if (pointsRedeemed > 0) {
                        currentPoints = Math.max(0, currentPoints - pointsRedeemed);
                    }
                    req.session.user.points = currentPoints;
                    // Optionally, persist to DB users table if available
                    const sql = 'UPDATE users SET points = ? WHERE id = ?';
                    connection.query(sql, [currentPoints, uid], (e) => {
                        if (e) console.error('Failed to update user points:', e);
                    });
                }
            } catch (e) {
                console.error('Error updating membership points:', e);
            }

            // Notifications for new paid order
            try {
                addNotification({
                    role: 'admin',
                    type: 'order',
                    message: `New paid order #${created.id} from ${req.session.user.username}.`,
                    link: '/admin/orders'
                });
                addNotification({
                    role: 'user',
                    userId: uid,
                    type: 'order',
                    message: `Your order #${created.id} has been placed successfully.`,
                    link: '/orders/' + encodeURIComponent(created.id)
                });
            } catch (e) {
                console.error('Failed to create notifications for new order:', e);
            }

            req.session.lastOrderId = created.id;
            req.flash('success', 'Payment successful. Order placed.');
            return res.redirect('/payment-processing');
        });
});

// Payment processing + success redirect
app.get('/payment-processing', checkAuthenticated, checkNotAdmin, (req, res) => {
    if (!req.session.lastOrderId) {
        return res.redirect('/orders');
    }
    res.render('payment_processing', { user: req.session.user });
});

app.get('/payment-success', checkAuthenticated, checkNotAdmin, (req, res) => {
    const id = req.session.lastOrderId;
    if (!id) return res.redirect('/orders');
    return res.redirect('/orders/' + encodeURIComponent(id));
});

// ---------------- NETS QR Routes ----------------
// Show NETS QR using services/nets with calculated total
app.get('/pay/nets/:id', checkAuthenticated, checkNotAdmin, (req, res) => {
    const id = req.params.id;
    const o = (inMemory.orders || []).find(x => String(x.id) === String(id));
    if (!o) return res.status(404).send('Order not found');
    // ensure total is available and accurate
    const total = Number(o.total || 0);
    // Pass cart total to service for QR generation
    try {
        req.body = req.body || {};
        req.body.cartTotal = total.toFixed(2);
    } catch (e) {}
    return netsService.generateQrCode(req, res);
});

// Render success status page (auto continues to finalize order)
app.get('/nets-qr/success', checkAuthenticated, checkNotAdmin, (req, res) => {
    res.render('netsTxnSuccessStatus', { message: 'Transaction Successful' });
});

// Finalize pending NETS order and redirect to order detail
app.post('/order/confirm', checkAuthenticated, checkNotAdmin, (req, res) => {
    const id = req.session.recentOrderId;
    if (!id) return res.redirect('/orders');
    const o = (inMemory.orders || []).find(x => String(x.id) === String(id));
    if (!o) return res.redirect('/orders');
    // mark as paid and update delivery estimate
    o.status = 'paid';
    if (!o.history) o.history = [];
    o.history.push({ status: 'paid', at: new Date().toISOString() });
    o.estimatedDelivery = estimateDeliveryDate(o.createdAt, o.deliveryOption);
    o.new = true;
    // clear cart
    req.session.cart = [];
    const uid = getUserIdFromSessionUser(req.session.user);
    if (uid) saveCartToDB(uid, req.session.cart, () => {});
    persistStore(() => {
        res.redirect('/orders/' + encodeURIComponent(id));
    });
});

// Render failure status page (auto redirects back to cart)
app.get('/nets-qr/fail', checkAuthenticated, checkNotAdmin, (req, res) => {
    res.render('netsTxnFailStatus', { message: 'Transaction Failed' });
});

// Redirect user to cart and show failure prompt
app.get('/nets-qr/fail/redirect', checkAuthenticated, checkNotAdmin, (req, res) => {
    // Use a query param so cart page can show a prompt
    res.redirect('/cart?paymentFailed=1');
});

// ---------------- SSE: NETS Payment Status ----------------
// Endpoint to stream real-time payment status updates via Server-Sent Events (SSE)
app.get('/sse/payment-status/:txnRetrievalRef', async (req, res) => {
    res.set({
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
    });

    const txnRetrievalRef = req.params.txnRetrievalRef;
    let pollCount = 0;
    const maxPolls = 60; // 5 minutes if polling every 5s
    let frontendTimeoutStatus = 0;

    const interval = setInterval(async () => {
        pollCount++;

        try {
            // Call the NETS query API
            const response = await axios.post(
                'https://sandbox.nets.openapipaas.com/api/v1/common/payments/nets-qr/query',
                { txn_retrieval_ref: txnRetrievalRef, frontend_timeout_status: frontendTimeoutStatus },
                {
                    headers: {
                        'api-key': process.env.API_KEY,
                        'project-id': process.env.PROJECT_ID,
                        'Content-Type': 'application/json'
                    }
                }
            );

            console.log('Polling response:', response.data);
            // Send the full response to the frontend
            res.write(`data: ${JSON.stringify(response.data)}\n\n`);

            const resData = response.data.result && response.data.result.data ? response.data.result.data : {};

            // Decide when to end polling and close the connection
            // Check if payment is successful
            if (resData.response_code == '00' && resData.txn_status === 1) {
                // Payment success: send a success message
                res.write(`data: ${JSON.stringify({ success: true })}\n\n`);
                clearInterval(interval);
                res.end();
            } else if (frontendTimeoutStatus == 1 && resData && (resData.response_code !== '00' || resData.txn_status === 2)) {
                // Payment failure: send a fail message
                res.write(`data: ${JSON.stringify({ fail: true, ...resData })}\n\n`);
                clearInterval(interval);
                res.end();
            }
        } catch (err) {
            clearInterval(interval);
            res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
            res.end();
        }

        // Timeout
        if (pollCount >= maxPolls) {
            clearInterval(interval);
            frontendTimeoutStatus = 1;
            res.write(`data: ${JSON.stringify({ fail: true, error: 'Timeout' })}\n\n`);
            res.end();
        }
    }, 5000);

    req.on('close', () => {
        clearInterval(interval);
    });
});

// ---------------- PayPal Order APIs ----------------
function httpRequestJson(urlString, { method = 'GET', headers = {}, body = null } = {}) {
    return new Promise((resolve, reject) => {
        try {
            const u = new URL(urlString);
            const opts = {
                method,
                hostname: u.hostname,
                path: u.pathname + (u.search || ''),
                headers
            };
            const reqHttps = https.request(opts, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => {
                    const status = res.statusCode || 0;
                    const isJson = (res.headers['content-type'] || '').includes('application/json');
                    if (!data) return resolve({ status, headers: res.headers, data: null });
                    try {
                        const parsed = isJson ? JSON.parse(data) : JSON.parse(data);
                        resolve({ status, headers: res.headers, data: parsed });
                    } catch (e) {
                        // non JSON fallback
                        resolve({ status, headers: res.headers, data: data });
                    }
                });
            });
            reqHttps.on('error', reject);
            if (body) reqHttps.write(body);
            reqHttps.end();
        } catch (e) {
            reject(e);
        }
    });
}

async function paypalGetAccessToken() {
    if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
        throw new Error('PayPal credentials not configured');
    }
    const tokenUrl = PAYPAL_API_BASE + '/v1/oauth2/token';
    const auth = Buffer.from(PAYPAL_CLIENT_ID + ':' + PAYPAL_CLIENT_SECRET).toString('base64');
    const body = 'grant_type=client_credentials';
    const { status, data } = await httpRequestJson(tokenUrl, {
        method: 'POST',
        headers: {
            'Authorization': 'Basic ' + auth,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(body)
        },
        body
    });
    if (status < 200 || status >= 300) {
        throw new Error('PayPal token request failed: ' + status + ' ' + JSON.stringify(data));
    }
    return data && data.access_token;
}

async function paypalCreateOrderRemote(totalValue) {
    const accessToken = await paypalGetAccessToken();
    const url = PAYPAL_API_BASE + '/v2/checkout/orders';
    const payload = JSON.stringify({
        intent: 'CAPTURE',
        purchase_units: [
            {
                amount: {
                    currency_code: PAYPAL_CURRENCY,
                    value: totalValue
                }
            }
        ]
    });
    const { status, data } = await httpRequestJson(url, {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + accessToken,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
        },
        body: payload
    });
    if (status < 200 || status >= 300) {
        throw new Error('PayPal create order failed: ' + status + ' ' + JSON.stringify(data));
    }
    return data;
}

async function paypalCaptureOrderRemote(orderId) {
    const accessToken = await paypalGetAccessToken();
    const url = PAYPAL_API_BASE + '/v2/checkout/orders/' + encodeURIComponent(orderId) + '/capture';
    const { status, data } = await httpRequestJson(url, {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + accessToken,
            'Content-Type': 'application/json'
        },
        body: ''
    });
    if (status < 200 || status >= 300) {
        throw new Error('PayPal capture failed: ' + status + ' ' + JSON.stringify(data));
    }
    return data;
}

async function paypalRefundCaptureRemote(captureId, amount, currency) {
    const accessToken = await paypalGetAccessToken();
    const url = PAYPAL_API_BASE + '/v2/payments/captures/' + encodeURIComponent(captureId) + '/refund';
    
    // If amount and currency are provided, do partial refund, otherwise full refund
    const payload = amount && currency ? JSON.stringify({
        amount: {
            value: amount,
            currency_code: currency
        }
    }) : '{}';
    
    const { status, data } = await httpRequestJson(url, {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + accessToken,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
        },
        body: payload
    });
    if (status < 200 || status >= 300) {
        throw new Error('PayPal refund failed: ' + status + ' ' + JSON.stringify(data));
    }
    return data;
}

// Create PayPal order using current cart + delivery selection
app.post('/api/paypal/create-order', checkAuthenticated, checkNotAdmin, async (req, res) => {
    try {
        const { deliveryOption, usePointsFreeDelivery } = req.body || {};
        const baseCart = req.session.cart || [];
        const cart = Array.isArray(req.session.selectedCartItems) && req.session.selectedCartItems.length
            ? req.session.selectedCartItems
            : baseCart;
        if (!cart || cart.length === 0) {
            return res.status(400).json({ error: 'Cart is empty' });
        }
        if (!req.session.delivery) {
            return res.status(400).json({ error: 'Missing delivery details' });
        }

        const subtotal = cart.reduce((s, it) => s + (Number(it.price || 0) * Number(it.quantity || 0)), 0);

        const now = new Date();
        const cutoffHour = 13; // 1pm
        let deliveryCost = 10;
        let pointsRedeemed = 0;
        let finalDeliveryOption = (deliveryOption || 'normal');

        if (finalDeliveryOption === 'one-day') {
            if (now.getHours() >= cutoffHour) {
                return res.status(400).json({ error: 'One-day delivery must be ordered before 1pm.' });
            }
            deliveryCost = 25;
        }

        const membership = buildMembershipSummary(req.session.user || {});
        const wantsFreeDelivery = usePointsFreeDelivery === true || usePointsFreeDelivery === 'on' || usePointsFreeDelivery === '1';
        if (wantsFreeDelivery && finalDeliveryOption === 'normal' && membership.points >= REDEEM_POINTS_FREE_DELIVERY) {
            deliveryCost = 0;
            pointsRedeemed = REDEEM_POINTS_FREE_DELIVERY;
        }

        const total = Number(subtotal) + Number(deliveryCost);
        const totalStr = total.toFixed(2);

        // Save pending selection in session for capture step
        req.session.pendingCheckout = {
            deliveryOption: finalDeliveryOption,
            deliveryCost,
            subtotal,
            pointsRedeemed
        };

        const created = await paypalCreateOrderRemote(totalStr);
        return res.json({ id: created && created.id });
    } catch (e) {
        console.error('PayPal create-order error:', e);
        return res.status(500).json({ error: 'Failed to create PayPal order' });
    }
});

// Capture PayPal order, then create internal order and redirect
app.post('/api/paypal/capture-order', checkAuthenticated, checkNotAdmin, async (req, res) => {
    try {
        const { orderID } = req.body || {};
        if (!orderID) return res.status(400).json({ error: 'Missing orderID' });

        const capture = await paypalCaptureOrderRemote(orderID);
        const status = (capture && capture.status) || '';
        if (status !== 'COMPLETED') {
            return res.status(400).json({ error: 'Payment not completed', details: capture });
        }

        // Build internal order from session data
        const baseCart = req.session.cart || [];
        const cart = Array.isArray(req.session.selectedCartItems) && req.session.selectedCartItems.length
            ? req.session.selectedCartItems
            : baseCart;
        const pending = req.session.pendingCheckout || {};
        const subtotal = pending.subtotal != null ? Number(pending.subtotal) : cart.reduce((s, it) => s + (Number(it.price || 0) * Number(it.quantity || 0)), 0);
        const deliveryCost = Number(pending.deliveryCost || 0);
        const pointsRedeemed = Number(pending.pointsRedeemed || 0);
        const deliveryOption = pending.deliveryOption || 'normal';
        const total = Number(subtotal) + Number(deliveryCost);

        const orderBase = {
            userId: getUserIdFromSessionUser(req.session.user),
            items: cart.slice(),
            subtotal,
            deliveryOption,
            deliveryCost,
            total,
            paymentMethod: 'paypal',
            delivery: req.session.delivery || null
        };

        const toCreate = Object.assign({}, orderBase, {
            status: 'paid',
            paymentDetails: {
                method: 'paypal',
                paypalOrderId: orderID
            },
            deliveryStatus: 'processing',
            membership: {
                pointsEarned: Math.floor(subtotal * POINTS_PER_DOLLAR),
                pointsRedeemed: pointsRedeemed
            }
        });

        // Create order in our store
        addOrder(toCreate, (err, created) => {
            if (err || !created || !created.id) {
                console.error('Order create warning (paypal):', err);
                return res.status(500).json({ error: 'Could not create order' });
            }

            // Deduct stock
            try {
                (created.items || []).forEach(item => {
                    const pid = item.productId || item.id;
                    const qty = Number(item.quantity) || 0;
                    if (!pid || qty <= 0) return;
                    const sql = 'UPDATE products SET quantity = GREATEST(quantity - ?, 0) WHERE id = ?';
                    connection.query(sql, [qty, pid], (e) => {
                        if (e) console.error('Failed to deduct stock for product', pid, e);
                    });
                });
            } catch (e) {
                console.error('Error during stock deduction:', e);
            }

            // Clear selected items/cart
            if (Array.isArray(req.session.selectedCartItems) && req.session.selectedCartItems.length) {
                const selectedIds = new Set(req.session.selectedCartItems.map(it => String(it.productId)));
                req.session.cart = (req.session.cart || []).filter(it => !selectedIds.has(String(it.productId)));
                req.session.selectedCartItems = [];
            } else {
                req.session.cart = [];
            }
            const uid = getUserIdFromSessionUser(req.session.user);
            if (uid) saveCartToDB(uid, req.session.cart, () => {});

            // Update points
            try {
                if (req.session.user && uid) {
                    const earned = Math.floor(subtotal * POINTS_PER_DOLLAR);
                    let currentPoints = Number(req.session.user.points || 0) || 0;
                    currentPoints += earned;
                    if (pointsRedeemed > 0) currentPoints = Math.max(0, currentPoints - pointsRedeemed);
                    req.session.user.points = currentPoints;
                    const sql = 'UPDATE users SET points = ? WHERE id = ?';
                    connection.query(sql, [currentPoints, uid], (e) => {
                        if (e) console.error('Failed to update user points:', e);
                    });
                }
            } catch (e) {
                console.error('Error updating membership points:', e);
            }

            // Notifications
            try {
                addNotification({
                    role: 'admin',
                    type: 'order',
                    message: `New paid order #${created.id} from ${req.session.user.username}.`,
                    link: '/admin/orders'
                });
                addNotification({
                    role: 'user',
                    userId: uid,
                    type: 'order',
                    message: `Your order #${created.id} has been placed successfully.`,
                    link: '/orders/' + encodeURIComponent(created.id)
                });
            } catch (e) {
                console.error('Failed to create notifications for new order:', e);
            }

            // Cleanup pending selection
            req.session.pendingCheckout = null;

            req.session.lastOrderId = created.id;
            return res.json({ success: true, orderId: created.id, redirect: '/orders/' + encodeURIComponent(created.id) });
        });
    } catch (e) {
        console.error('PayPal capture-order error:', e);
        return res.status(500).json({ error: 'Failed to capture PayPal order' });
    }
});

// API endpoint to process PayPal refund for a specific order
app.post('/api/paypal/refund-order', checkAuthenticated, checkAdmin, async (req, res) => {
    try {
        const { orderId, amount, note } = req.body || {};
        
        if (!orderId) {
            return res.status(400).json({ error: 'Missing orderId' });
        }

        // Find the order
        const order = (inMemory.orders || []).find(o => String(o.id) === String(orderId));
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }

        // Check if payment was made via PayPal
        const paymentMethod = order.paymentMethod || (order.paymentDetails && order.paymentDetails.method);
        const paypalOrderId = order.paymentDetails && order.paymentDetails.paypalOrderId;

        if (paymentMethod !== 'paypal' || !paypalOrderId) {
            return res.status(400).json({ 
                error: 'Order was not paid via PayPal',
                paymentMethod: paymentMethod 
            });
        }

        // Get the capture ID from PayPal
        const accessToken = await paypalGetAccessToken();
        const orderDetailsUrl = PAYPAL_API_BASE + '/v2/checkout/orders/' + encodeURIComponent(paypalOrderId);
        const { status: orderStatus, data: orderData } = await httpRequestJson(orderDetailsUrl, {
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + accessToken,
                'Content-Type': 'application/json'
            }
        });

        if (orderStatus < 200 || orderStatus >= 300 || !orderData) {
            return res.status(500).json({ 
                error: 'Failed to retrieve PayPal order details',
                status: orderStatus 
            });
        }

        // Extract capture ID
        const captureId = orderData.purchase_units && 
                        orderData.purchase_units[0] && 
                        orderData.purchase_units[0].payments && 
                        orderData.purchase_units[0].payments.captures && 
                        orderData.purchase_units[0].payments.captures[0] && 
                        orderData.purchase_units[0].payments.captures[0].id;

        if (!captureId) {
            return res.status(400).json({ 
                error: 'No capture found for this PayPal order',
                paypalOrderId: paypalOrderId 
            });
        }

        // Process the refund (full or partial)
        const refundAmount = amount ? String(Number(amount).toFixed(2)) : String(Number(order.total).toFixed(2));
        const refundData = await paypalRefundCaptureRemote(captureId, refundAmount, PAYPAL_CURRENCY);

        console.log('PayPal refund processed via API:', refundData);

        // Update order status
        order.status = 'refunded';
        order.refundDetails = {
            paypalRefundId: refundData.id,
            paypalRefundStatus: refundData.status,
            refundedAmount: refundAmount,
            refundedAt: new Date().toISOString(),
            note: note || 'Admin-initiated refund via API'
        };
        if (!order.history) order.history = [];
        order.history.push({
            status: 'refunded via PayPal',
            at: new Date().toISOString(),
            refundId: refundData.id
        });

        persistStore(() => {});

        return res.json({
            success: true,
            message: 'Refund processed successfully',
            refund: {
                id: refundData.id,
                status: refundData.status,
                amount: refundAmount,
                currency: PAYPAL_CURRENCY
            }
        });
    } catch (e) {
        console.error('PayPal refund API error:', e);
        return res.status(500).json({ 
            error: 'Failed to process PayPal refund',
            details: e.message 
        });
    }
});

// ---------------- Stripe Checkout Endpoints ----------------

// Create Stripe checkout session
app.post('/api/stripe/create-checkout-session', checkAuthenticated, checkNotAdmin, async (req, res) => {
    if (!stripe) {
        return res.status(500).json({ error: 'Stripe not configured' });
    }

    try {
        const { deliveryOption, usePointsFreeDelivery } = req.body || {};
        const baseCart = req.session.cart || [];
        const cart = Array.isArray(req.session.selectedCartItems) && req.session.selectedCartItems.length
            ? req.session.selectedCartItems
            : baseCart;
        
        if (!cart || cart.length === 0) {
            return res.status(400).json({ error: 'Cart is empty' });
        }
        if (!req.session.delivery) {
            return res.status(400).json({ error: 'Missing delivery details' });
        }

        const subtotal = cart.reduce((s, it) => s + (Number(it.price || 0) * Number(it.quantity || 0)), 0);

        const now = new Date();
        const cutoffHour = 13;
        let deliveryCost = 10;
        let pointsRedeemed = 0;
        let finalDeliveryOption = (deliveryOption || 'normal');

        if (finalDeliveryOption === 'one-day') {
            if (now.getHours() >= cutoffHour) {
                return res.status(400).json({ error: 'One-day delivery must be ordered before 1pm.' });
            }
            deliveryCost = 25;
        }

        const membership = buildMembershipSummary(req.session.user || {});
        const wantsFreeDelivery = usePointsFreeDelivery === true || usePointsFreeDelivery === 'on' || usePointsFreeDelivery === '1';
        if (wantsFreeDelivery && finalDeliveryOption === 'normal' && membership.points >= REDEEM_POINTS_FREE_DELIVERY) {
            deliveryCost = 0;
            pointsRedeemed = REDEEM_POINTS_FREE_DELIVERY;
        }

        const total = Number(subtotal) + Number(deliveryCost);

        // Save pending checkout data in session
        req.session.pendingCheckout = {
            deliveryOption: finalDeliveryOption,
            deliveryCost,
            subtotal,
            pointsRedeemed
        };

        // Create line items for Stripe
        const lineItems = cart.map(item => ({
            price_data: {
                currency: STRIPE_CURRENCY,
                product_data: {
                    name: item.productName || item.name || 'Product',
                    images: item.image ? [`${req.protocol}://${req.get('host')}/images/${item.image}`] : []
                },
                unit_amount: Math.round(Number(item.price) * 100) // Convert to cents
            },
            quantity: Number(item.quantity) || 1
        }));

        // Add delivery as a line item
        if (deliveryCost > 0) {
            lineItems.push({
                price_data: {
                    currency: STRIPE_CURRENCY,
                    product_data: {
                        name: finalDeliveryOption === 'one-day' ? 'One-Day Delivery' : 'Standard Delivery'
                    },
                    unit_amount: Math.round(deliveryCost * 100)
                },
                quantity: 1
            });
        }

        // Create Stripe checkout session
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            success_url: `${req.protocol}://${req.get('host')}/stripe/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${req.protocol}://${req.get('host')}/checkout`,
            client_reference_id: String(getUserIdFromSessionUser(req.session.user)),
            metadata: {
                userId: String(getUserIdFromSessionUser(req.session.user)),
                deliveryOption: finalDeliveryOption,
                pointsRedeemed: String(pointsRedeemed)
            }
        });

        return res.json({ id: session.id, url: session.url });
    } catch (e) {
        console.error('Stripe checkout session error:', e);
        return res.status(500).json({ error: 'Failed to create checkout session', details: e.message });
    }
});

// Stripe success callback
app.get('/stripe/success', checkAuthenticated, checkNotAdmin, async (req, res) => {
    const sessionId = req.query.session_id;
    
    if (!sessionId || !stripe) {
        req.flash('error', 'Invalid payment session');
        return res.redirect('/checkout');
    }

    try {
        // Retrieve the session from Stripe
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        
        if (session.payment_status !== 'paid') {
            req.flash('error', 'Payment not completed');
            return res.redirect('/checkout');
        }

        // Build internal order from session data
        const baseCart = req.session.cart || [];
        const cart = Array.isArray(req.session.selectedCartItems) && req.session.selectedCartItems.length
            ? req.session.selectedCartItems
            : baseCart;
        
        const pending = req.session.pendingCheckout || {};
        const subtotal = pending.subtotal != null ? Number(pending.subtotal) : cart.reduce((s, it) => s + (Number(it.price || 0) * Number(it.quantity || 0)), 0);
        const deliveryCost = Number(pending.deliveryCost || 0);
        const pointsRedeemed = Number(pending.pointsRedeemed || 0);
        const deliveryOption = pending.deliveryOption || 'normal';
        const total = Number(subtotal) + Number(deliveryCost);

        const orderBase = {
            userId: getUserIdFromSessionUser(req.session.user),
            items: cart.slice(),
            subtotal,
            deliveryOption,
            deliveryCost,
            total,
            paymentMethod: 'stripe',
            delivery: req.session.delivery || null
        };

        const toCreate = Object.assign({}, orderBase, {
            status: 'paid',
            paymentDetails: {
                method: 'stripe',
                stripeSessionId: sessionId,
                stripePaymentIntentId: session.payment_intent
            },
            deliveryStatus: 'processing',
            membership: {
                pointsEarned: Math.floor(subtotal * POINTS_PER_DOLLAR),
                pointsRedeemed: pointsRedeemed
            }
        });

        // Create order in our store
        addOrder(toCreate, (err, created) => {
            if (err || !created || !created.id) {
                console.error('Order create warning (stripe):', err);
                req.flash('error', 'Payment successful but order creation failed. Please contact support.');
                return res.redirect('/orders');
            }

            // Deduct stock
            try {
                (created.items || []).forEach(item => {
                    const pid = item.productId || item.id;
                    const qty = Number(item.quantity) || 0;
                    if (!pid || qty <= 0) return;
                    const sql = 'UPDATE products SET quantity = GREATEST(quantity - ?, 0) WHERE id = ?';
                    connection.query(sql, [qty, pid], (e) => {
                        if (e) console.error('Failed to deduct stock for product', pid, e);
                    });
                });
            } catch (e) {
                console.error('Error during stock deduction:', e);
            }

            // Clear selected items/cart
            if (Array.isArray(req.session.selectedCartItems) && req.session.selectedCartItems.length) {
                const selectedIds = new Set(req.session.selectedCartItems.map(it => String(it.productId)));
                req.session.cart = (req.session.cart || []).filter(it => !selectedIds.has(String(it.productId)));
                req.session.selectedCartItems = [];
            } else {
                req.session.cart = [];
            }
            const uid = getUserIdFromSessionUser(req.session.user);
            if (uid) saveCartToDB(uid, req.session.cart, () => {});

            // Update points
            try {
                if (req.session.user && uid) {
                    const earned = Math.floor(subtotal * POINTS_PER_DOLLAR);
                    let currentPoints = Number(req.session.user.points || 0) || 0;
                    currentPoints += earned;
                    if (pointsRedeemed > 0) currentPoints = Math.max(0, currentPoints - pointsRedeemed);
                    req.session.user.points = currentPoints;
                    const sql = 'UPDATE users SET points = ? WHERE id = ?';
                    connection.query(sql, [currentPoints, uid], (e) => {
                        if (e) console.error('Failed to update user points:', e);
                    });
                }
            } catch (e) {
                console.error('Error updating membership points:', e);
            }

            // Notifications
            try {
                addNotification({
                    role: 'admin',
                    type: 'order',
                    message: `New paid order #${created.id} from ${req.session.user.username} (Stripe).`,
                    link: '/admin/orders'
                });
                addNotification({
                    role: 'user',
                    userId: uid,
                    type: 'order',
                    message: `Your order #${created.id} has been placed successfully.`,
                    link: '/orders/' + encodeURIComponent(created.id)
                });
            } catch (e) {
                console.error('Failed to create notifications for new order:', e);
            }

            // Cleanup pending selection
            req.session.pendingCheckout = null;
            req.session.lastOrderId = created.id;
            
            req.flash('success', 'Payment successful! Your order has been placed.');
            return res.redirect('/orders/' + encodeURIComponent(created.id));
        });
    } catch (e) {
        console.error('Stripe success handler error:', e);
        req.flash('error', 'An error occurred processing your payment');
        return res.redirect('/checkout');
    }
});

// QR payment page (shows QR and allows simulating confirmation)
app.get('/pay/qr/:id', checkAuthenticated, checkNotAdmin, (req, res) => {
    const id = req.params.id;
    const o = (inMemory.orders || []).find(x => String(x.id) === String(id));
    if (!o) return res.status(404).send('Order not found');
    res.render('pay_qr', { order: o, user: req.session.user });
});

// Confirm QR payment (simulate the callback from payment app)
app.post('/pay/qr/:id/confirm', checkAuthenticated, checkNotAdmin, (req, res) => {
    const id = req.params.id;
    // mark order as paid
    const o = (inMemory.orders || []).find(x => String(x.id) === String(id));
    if (!o) return res.status(404).send('Order not found');
    o.status = 'paid';
    if (!o.history) o.history = [];
    o.history.push({ status: 'paid', at: new Date().toISOString() });
    // update delivery estimate
    o.estimatedDelivery = estimateDeliveryDate(o.createdAt, o.deliveryOption);
    o.new = true;
    persistStore(() => {
        // clear cart
        req.session.cart = [];
        const uid = getUserIdFromSessionUser(req.session.user);
        if (uid) saveCartToDB(uid, req.session.cart, () => {});
        return res.redirect('/orders/' + encodeURIComponent(o.id));
    });
});

// User Help Center
app.get('/help-center', checkAuthenticated, checkNotAdmin, (req, res) => {
    const userId = getUserIdFromSessionUser(req.session.user);
    getOrdersByUser(userId, (err, orders) => {
        if (err) {
            console.error('Failed to load orders for help center:', err);
            req.flash('error', 'Could not load orders');
            return res.redirect('/orders');
        }
        const eligibleAddressOrders = (orders || []).filter(o => {
            const status = (o.deliveryStatus || '').toLowerCase();
            // Treat both "packed" and "item packed" as eligible
            return status === 'packed' || status === 'item packed';
        });
        const refundableOrders = (orders || []).filter(o => (o.status || '').toLowerCase() === 'paid');
        const errors = req.flash('error');
        const success = req.flash('success');
        res.render('help_center', {
            user: req.session.user,
            eligibleAddressOrders,
            refundableOrders,
            errors,
            success
        });
    });
});

app.post('/help-center/address-change', checkAuthenticated, checkNotAdmin, (req, res) => {
    const userId = getUserIdFromSessionUser(req.session.user);
    const { orderId, newAddress, reason } = req.body || {};
    if (!orderId || !newAddress) {
        req.flash('error', 'Please select an order and provide a new address.');
        return res.redirect('/help-center');
    }
    // Ensure order belongs to user and is in packed state
    getOrdersByUser(userId, (err, orders) => {
        if (err) {
            console.error('Failed to load orders for address change:', err);
            req.flash('error', 'Could not submit request');
            return res.redirect('/help-center');
        }
        const order = (orders || []).find(o => String(o.id) === String(orderId));
        if (!order) {
            req.flash('error', 'Order not found.');
            return res.redirect('/help-center');
        }
        const status = (order.deliveryStatus || '').toLowerCase();
        if (status !== 'packed') {
            req.flash('error', 'Address change is only allowed when the order status is "item packed".');
            return res.redirect('/help-center');
        }
        addAddressChangeRequest({
            userId,
            username: req.session.user.username,
            orderId: order.id,
            newAddress,
            reason
        }, (e) => {
            if (e) {
                console.error('Failed to save address change request:', e);
                req.flash('error', 'Could not submit request. Please try again.');
            } else {
                req.flash('success', 'Address change request submitted. Our team will review it.');
                // Notify admin about new address change request
                addNotification({
                    role: 'admin',
                    type: 'address',
                    message: `New address change request for order #${order.id} from ${req.session.user.username}.`,
                    link: '/admin/help-center'
                });
                // Notify user confirming submission
                addNotification({
                    role: 'user',
                    userId,
                    type: 'address',
                    message: `Your address change request for order #${order.id} has been submitted.`,
                    link: '/help-center'
                });
            }
            return res.redirect('/help-center');
        });
    });
});

app.post('/help-center/refund', checkAuthenticated, checkNotAdmin, (req, res) => {
    const userId = getUserIdFromSessionUser(req.session.user);
    const { orderId, reason } = req.body || {};
    if (!orderId || !reason) {
        req.flash('error', 'Please select an order and provide a reason for refund.');
        return res.redirect('/help-center');
    }
    getOrdersByUser(userId, (err, orders) => {
        if (err) {
            console.error('Failed to load orders for refund:', err);
            req.flash('error', 'Could not submit request');
            return res.redirect('/help-center');
        }
        const order = (orders || []).find(o => String(o.id) === String(orderId));
        if (!order) {
            req.flash('error', 'Order not found.');
            return res.redirect('/help-center');
        }
        if ((order.status || '').toLowerCase() !== 'paid') {
            req.flash('error', 'Only paid orders can be refunded.');
            return res.redirect('/help-center');
        }
        addRefundRequest({
            userId,
            username: req.session.user.username,
            orderId: order.id,
            reason
        }, (e) => {
            if (e) {
                console.error('Failed to save refund request:', e);
                req.flash('error', 'Could not submit refund request.');
            } else {
                req.flash('success', 'Refund request submitted. We will notify you once it is reviewed.');
                // Notify admin about new refund request
                addNotification({
                    role: 'admin',
                    type: 'refund',
                    message: `New refund request for order #${order.id} from ${req.session.user.username}.`,
                    link: '/admin/help-center'
                });
                // Notify user confirming submission
                addNotification({
                    role: 'user',
                    userId,
                    type: 'refund',
                    message: `Your refund request for order #${order.id} has been submitted.`,
                    link: '/help-center'
                });
            }
            return res.redirect('/help-center');
        });
    });
});

// User: list orders
app.get('/orders', checkAuthenticated, (req, res) => {
    const uid = getUserIdFromSessionUser(req.session.user);
    getOrdersByUser(uid, (err, orders) => {
        // Ignore any error and always show the page
        if (err) {
            console.error('Failed to fetch orders:', err);
        }

        const safeOrders = (orders || []).map(o => {
            o.estimatedDelivery = estimateDeliveryDate(o.createdAt, o.deliveryOption);
            return o;
        });

        return res.render('orders', { orders: safeOrders, user: req.session.user });
    });
});

// User: order detail
app.get('/orders/:id', checkAuthenticated, (req, res) => {
    const id = req.params.id;
    const uid = getUserIdFromSessionUser(req.session.user);
    const o = (inMemory.orders || []).find(x => String(x.id) === String(id));
    if (!o) return res.status(404).send('Order not found');
    if (String(o.userId) !== String(uid) && !(req.session.user && req.session.user.role === 'admin')) return res.status(403).send('Access denied');
    o.estimatedDelivery = estimateDeliveryDate(o.createdAt, o.deliveryOption);
    res.render('order_detail', { order: o, user: req.session.user });
});

// User: invoice / print view for a single order
app.get('/orders/:id/invoice', checkAuthenticated, (req, res) => {
    const id = req.params.id;
    const uid = getUserIdFromSessionUser(req.session.user);
    const o = (inMemory.orders || []).find(x => String(x.id) === String(id));
    if (!o) {
        req.flash('error', 'Order not found.');
        return res.redirect('/orders');
    }

    // Only the owner user or an admin can view this invoice
    if (String(o.userId) !== String(uid) && !(req.session.user && req.session.user.role === 'admin')) {
        req.flash('error', 'You are not allowed to view this invoice.');
        return res.redirect('/orders');
    }

    // Ensure estimatedDelivery is present if the template ever needs it
    o.estimatedDelivery = estimateDeliveryDate(o.createdAt, o.deliveryOption);

    res.render('invoice', { order: o, user: req.session.user });
});

// Admin: view all orders
app.get('/admin/orders', checkAuthenticated, checkAdmin, (req, res) => {
    getAllOrders((err, orders) => {
        if (err) {
            console.error('Failed to fetch all orders:', err);
        }

        const safeOrders = (orders || []).map(o => {
            o.estimatedDelivery = estimateDeliveryDate(o.createdAt, o.deliveryOption);
            return o;
        });

        const errors = req.flash('error');
        const success = req.flash('success');
        return res.render('admin_orders', { orders: safeOrders, user: req.session.user, errors, success });
    });
});

// Admin: update order status
app.post('/admin/orders/:id/status', checkAuthenticated, checkAdmin, (req, res) => {
    const id = req.params.id;
    const status = req.body.status;
    if (!status) return res.redirect('/admin/orders');
    updateOrderStatus(id, status, (err, updated) => {
        if (err) {
            console.error('Failed to update order status:', err);
            req.flash('error', 'Could not update status. Please try again.');
        } else {
            req.flash('success', 'Status updated');
        }
        return res.redirect('/admin/orders');
    });
});


// Start the server
// Export app for tests and only start server when script is run directly
if (require.main === module) {
    const port = process.env.PORT || 3001;
    app.listen(port, () => {
        console.log('Server is running on http://localhost:' + port);
    });
}

module.exports = app;