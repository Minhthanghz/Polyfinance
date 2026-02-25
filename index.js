const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Only serve static files when running locally (not in serverless)
if (require.main === module) {
    app.use(express.static(path.join(__dirname)));
}

// --- DATABASE CONNECTION ---
const connectionString = process.env.DATABASE_URL || "postgresql://neondb_owner:npg_3zrZaqNKOWL4@ep-flat-salad-aiu8t97z-pooler.c-4.us-east-1.aws.neon.tech/neondb?sslmode=require";

const pool = new Pool({
    connectionString,
    ssl: { rejectUnauthorized: false },
    max: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

const SECRET_KEY = process.env.JWT_SECRET || "PFT_GLOBAL_SECURITY_0383154754";

// --- DATABASE INITIALIZATION ---
async function initDatabase() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                uid INTEGER UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                fullname VARCHAR(255),
                referral_code VARCHAR(50) UNIQUE,
                referred_by VARCHAR(50),
                usdt_balance NUMERIC(18,8) DEFAULT 0,
                pft_balance NUMERIC(18,8) DEFAULT 0,
                assigned_wallet TEXT,
                kyc_status INTEGER DEFAULT 0,
                kyc_fullname VARCHAR(255),
                kyc_id_number VARCHAR(100),
                total_investment NUMERIC(18,8) DEFAULT 0,
                mining_balance NUMERIC(18,8) DEFAULT 0,
                last_claim TIMESTAMP,
                security_2fa BOOLEAN DEFAULT FALSE,
                security_biometric BOOLEAN DEFAULT TRUE,
                security_email_alert BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                type VARCHAR(50) NOT NULL,
                amount NUMERIC(18,8),
                status VARCHAR(20) DEFAULT 'PENDING',
                address TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS wallet_requests (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                status VARCHAR(20) DEFAULT 'PENDING',
                created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS p2p_orders (
                id SERIAL PRIMARY KEY,
                type VARCHAR(10) NOT NULL,
                price NUMERIC(18,2),
                stock NUMERIC(18,8),
                merchant_name VARCHAR(255),
                bank_info TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS p2p_trades (
                id SERIAL PRIMARY KEY,
                order_id INTEGER REFERENCES p2p_orders(id),
                user_id INTEGER REFERENCES users(id),
                amount NUMERIC(18,8),
                amount_vnd NUMERIC(18,0),
                user_bank_info TEXT,
                type VARCHAR(10),
                status VARCHAR(20) DEFAULT 'PENDING',
                admin_note TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);
        // Add columns that may be missing on existing tables
        const alterStatements = [
            'ALTER TABLE users ADD COLUMN IF NOT EXISTS kyc_fullname VARCHAR(255)',
            'ALTER TABLE users ADD COLUMN IF NOT EXISTS kyc_id_number VARCHAR(100)',
            'ALTER TABLE users ADD COLUMN IF NOT EXISTS security_2fa BOOLEAN DEFAULT FALSE',
            'ALTER TABLE users ADD COLUMN IF NOT EXISTS security_biometric BOOLEAN DEFAULT TRUE',
            'ALTER TABLE users ADD COLUMN IF NOT EXISTS security_email_alert BOOLEAN DEFAULT FALSE'
        ];
        for (const sql of alterStatements) {
            try { await client.query(sql); } catch (e) { /* column may already exist */ }
        }

        console.log('Database tables initialized successfully');
    } catch (e) {
        console.error('Database initialization error:', e.message);
    } finally {
        client.release();
    }
}

// Initialize database on first load
let dbInitialized = false;
async function ensureDb() {
    if (!dbInitialized) {
        await initDatabase();
        dbInitialized = true;
    }
}

// --- MIDDLEWARE ---
const authUser = (req, res, next) => {
    try {
        const token = req.headers.authorization.split(" ")[1];
        const decoded = jwt.decode(token, SECRET_KEY);
        req.userId = decoded.id;
        next();
    } catch (e) { res.status(401).json({ message: "Phiên đăng nhập hết hạn" }); }
};

// Ensure DB is initialized before handling requests
app.use(async (req, res, next) => {
    try { await ensureDb(); } catch (e) { console.error('DB init error:', e.message); }
    next();
});

// --- HỆ THỐNG AUTH (LOGIN/REGISTER/AFFILIATE) ---
app.post('/api/auth/register', async (req, res) => {
    const { name, email, pass, ref } = req.body;
    const hashedPass = await bcrypt.hash(pass, 10);
    const uid = Math.floor(100000 + Math.random() * 900000);
    const refCode = "PFT" + uid;

    try {
        const result = await pool.query(
            'INSERT INTO users (uid, email, password_hash, fullname, referral_code, referred_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, uid',
            [uid, email, hashedPass, name, refCode, ref || null]
        );
        const user = result.rows[0];
        const token = jwt.encode({ id: user.id }, SECRET_KEY);
        res.json({ message: "Đăng ký thành công", token, email: user.email, uid: user.uid });
    } catch (e) {
        console.error(e);
        res.status(400).json({ message: "Email đã tồn tại" });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, pass } = req.body;
    try {
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

        if (user.rows.length > 0 && await bcrypt.compare(pass, user.rows[0].password_hash)) {
            const token = jwt.encode({ id: user.rows[0].id }, SECRET_KEY);
            res.json({ token, email: user.rows[0].email, uid: user.rows[0].uid });
        } else {
            res.status(401).json({ message: "Sai tài khoản hoặc mật khẩu" });
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: "Lỗi máy chủ" });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.json({ message: "Đăng xuất thành công" });
});

app.get('/api/auth/status', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.json({ loggedIn: false });
        const token = authHeader.split(" ")[1];
        const decoded = jwt.decode(token, SECRET_KEY);
        const user = await pool.query('SELECT id FROM users WHERE id = $1', [decoded.id]);
        res.json({ loggedIn: user.rows.length > 0 });
    } catch (e) { res.json({ loggedIn: false }); }
});

// --- USER DATA ---
app.get('/api/user/data', authUser, async (req, res) => {
    try {
        const user = await pool.query('SELECT * FROM users WHERE id = $1', [req.userId]);
        if (user.rows.length === 0) return res.status(404).json({ message: "Không tìm thấy người dùng" });
        const u = user.rows[0];
        delete u.password_hash;
        res.json(u);
    } catch (e) { res.status(500).json({ message: "Lỗi máy chủ" }); }
});

app.get('/api/user/profile', authUser, async (req, res) => {
    try {
        const user = await pool.query('SELECT * FROM users WHERE id = $1', [req.userId]);
        if (user.rows.length === 0) return res.status(404).json({ message: "Không tìm thấy" });
        const userData = user.rows[0];
        delete userData.password_hash;

        const refs = await pool.query('SELECT COUNT(*) as total FROM users WHERE referred_by = $1', [userData.referral_code]);
        userData.total_refs = refs.rows[0].total;

        res.json(userData);
    } catch (e) { res.status(500).json({ message: "Lỗi" }); }
});

app.get('/api/user/transactions', authUser, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC', [req.userId]);
        res.json(result.rows);
    } catch (e) { res.status(500).json({ message: "Lỗi tải lịch sử" }); }
});

app.get('/api/user/withdraw-history', authUser, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM transactions WHERE user_id = $1 AND type = \'RUT\' ORDER BY created_at DESC', [req.userId]);
        res.json(result.rows);
    } catch (e) { res.status(500).json({ message: "Lỗi" }); }
});

app.get('/api/user/check-uid', authUser, async (req, res) => {
    const { uid } = req.query;
    try {
        const result = await pool.query('SELECT fullname FROM users WHERE uid = $1', [uid]);
        if (result.rows.length > 0) {
            res.json({ found: true, name: result.rows[0].fullname });
        } else {
            res.json({ found: false });
        }
    } catch (e) { res.status(500).json({ message: "Lỗi" }); }
});

// --- SECURITY ENDPOINTS ---
app.get('/api/user/security-data', authUser, async (req, res) => {
    try {
        const user = await pool.query('SELECT security_2fa, security_biometric, security_email_alert FROM users WHERE id = $1', [req.userId]);
        if (user.rows.length === 0) return res.status(404).json({ message: "Không tìm thấy" });
        res.json(user.rows[0]);
    } catch (e) { res.status(500).json({ message: "Lỗi" }); }
});

app.post('/api/user/update-password', authUser, async (req, res) => {
    const { oldPass, newPass } = req.body;
    try {
        const user = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.userId]);
        if (user.rows.length === 0) return res.status(404).json({ message: "Không tìm thấy" });

        const valid = await bcrypt.compare(oldPass, user.rows[0].password_hash);
        if (!valid) return res.status(400).json({ message: "Mật khẩu hiện tại không chính xác" });

        const newHash = await bcrypt.hash(newPass, 10);
        await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, req.userId]);
        res.json({ message: "Cập nhật mật khẩu thành công" });
    } catch (e) { res.status(500).json({ message: "Lỗi máy chủ" }); }
});

app.post('/api/user/update-security-opt', authUser, async (req, res) => {
    const { type, status } = req.body;
    const columnMap = {
        '2fa_auth': 'security_2fa',
        'biometric': 'security_biometric',
        'email_alert': 'security_email_alert'
    };
    const col = columnMap[type];
    if (!col) return res.status(400).json({ message: "Loại cài đặt không hợp lệ" });

    try {
        await pool.query(`UPDATE users SET ${col} = $1 WHERE id = $2`, [status, req.userId]);
        res.json({ message: "Đã cập nhật" });
    } catch (e) { res.status(500).json({ message: "Lỗi" }); }
});

// --- KYC ENDPOINT ---
app.post('/api/user/kyc-submit', authUser, async (req, res) => {
    const { fullname, idNumber } = req.body;
    try {
        await pool.query('UPDATE users SET kyc_fullname = $1, kyc_id_number = $2, kyc_status = 2 WHERE id = $3', [fullname, idNumber, req.userId]);
        res.json({ message: "Đã gửi yêu cầu KYC" });
    } catch (e) { res.status(500).json({ message: "Lỗi gửi KYC" }); }
});

// --- SWAP ---
app.post('/api/user/swap', authUser, async (req, res) => {
    const { amount, direction, price } = req.body;
    const amt = parseFloat(amount);
    try {
        const user = await pool.query('SELECT usdt_balance, pft_balance FROM users WHERE id = $1', [req.userId]);
        const u = user.rows[0];

        await pool.query('BEGIN');
        if (direction === 'USDT_TO_PFT') {
            if (u.usdt_balance < amt) throw new Error("Không đủ USDT");
            const pftAmt = amt / price;
            await pool.query('UPDATE users SET usdt_balance = usdt_balance - $1, pft_balance = pft_balance + $2 WHERE id = $3', [amt, pftAmt, req.userId]);
            await pool.query('INSERT INTO transactions (user_id, type, amount, status, address) VALUES ($1, $2, $3, $4, $5)', [req.userId, 'SWAP', -amt, 'SUCCESS', 'USDT -> PFT']);
            await pool.query('INSERT INTO transactions (user_id, type, amount, status, address) VALUES ($1, $2, $3, $4, $5)', [req.userId, 'SWAP', pftAmt, 'SUCCESS', 'PFT (Swap)']);
        } else {
            if (u.pft_balance < amt) throw new Error("Không đủ PFT");
            const usdtAmt = amt * price;
            await pool.query('UPDATE users SET pft_balance = pft_balance - $1, usdt_balance = usdt_balance + $2 WHERE id = $3', [amt, usdtAmt, req.userId]);
            await pool.query('INSERT INTO transactions (user_id, type, amount, status, address) VALUES ($1, $2, $3, $4, $5)', [req.userId, 'SWAP', -amt, 'SUCCESS', 'PFT -> USDT']);
            await pool.query('INSERT INTO transactions (user_id, type, amount, status, address) VALUES ($1, $2, $3, $4, $5)', [req.userId, 'SWAP', usdtAmt, 'SUCCESS', 'USDT (Swap)']);
        }

        await pool.query('COMMIT');
        res.json({ message: "Thành công" });
    } catch (e) {
        await pool.query('ROLLBACK');
        res.status(400).json({ message: e.message });
    }
});

// --- TRANSFER ---
app.post('/api/user/transfer', authUser, async (req, res) => {
    const { toUid, amount, asset } = req.body;
    const amt = parseFloat(amount);
    const col = asset === 'PFT' ? 'pft_balance' : 'usdt_balance';

    try {
        await pool.query('BEGIN');

        const sender = await pool.query(`SELECT uid, ${col} FROM users WHERE id = $1`, [req.userId]);
        if (sender.rows.length === 0 || sender.rows[0][col] < amt) {
            throw new Error("Số dư không đủ");
        }

        const receiver = await pool.query('SELECT id FROM users WHERE uid = $1', [toUid]);
        if (receiver.rows.length === 0) {
            throw new Error("Không tìm thấy người dùng nhận");
        }
        const receiverId = receiver.rows[0].id;

        if (receiverId === req.userId) {
            throw new Error("Không thể chuyển tiền cho chính mình");
        }

        await pool.query(`UPDATE users SET ${col} = ${col} - $1 WHERE id = $2`, [amt, req.userId]);
        await pool.query(`UPDATE users SET ${col} = ${col} + $1 WHERE id = $2`, [amt, receiverId]);

        const updatedSender = await pool.query(`SELECT ${col} FROM users WHERE id = $1`, [req.userId]);
        const newBalance = updatedSender.rows[0][col];

        await pool.query('INSERT INTO transactions (user_id, type, amount, status, address) VALUES ($1, $2, $3, $4, $5)',
            [req.userId, 'TRANSFER_OUT', -amt, 'SUCCESS', `To UID: ${toUid}`]);
        await pool.query('INSERT INTO transactions (user_id, type, amount, status, address) VALUES ($1, $2, $3, $4, $5)',
            [receiverId, 'TRANSFER_IN', amt, 'SUCCESS', `From UID: ${sender.rows[0].uid || req.userId}`]);

        await pool.query('COMMIT');
        res.json({ message: "Chuyển tiền thành công", newBalance });
    } catch (e) {
        await pool.query('ROLLBACK');
        res.status(400).json({ message: e.message });
    }
});

// --- DEPOSIT / WITHDRAW ---
app.post('/api/admin/request-wallet', authUser, async (req, res) => {
    try {
        await pool.query('INSERT INTO wallet_requests (user_id) VALUES ($1)', [req.userId]);
        res.json({ message: "Đã gửi yêu cầu cấp ví" });
    } catch (e) { res.status(500).json({ message: "Lỗi gửi yêu cầu" }); }
});

app.post('/api/user/withdraw-request', authUser, async (req, res) => {
    const { amount, address } = req.body;
    try {
        const user = await pool.query('SELECT usdt_balance FROM users WHERE id = $1', [req.userId]);
        if (user.rows[0].usdt_balance < amount) return res.status(400).json({ message: "Số dư không đủ" });

        await pool.query('BEGIN');
        await pool.query('UPDATE users SET usdt_balance = usdt_balance - $1 WHERE id = $2', [amount, req.userId]);
        await pool.query('INSERT INTO transactions (user_id, type, amount, address, status) VALUES ($1, $2, $3, $4, $5)',
            [req.userId, 'RUT', -amount, address, 'PENDING']);
        await pool.query('COMMIT');
        res.json({ message: "Yêu cầu rút đang chờ duyệt" });
    } catch (e) {
        await pool.query('ROLLBACK');
        res.status(500).json({ message: "Lỗi yêu cầu rút" });
    }
});

// --- STAKING ---
app.post('/api/staking/create', authUser, async (req, res) => {
    const { amount, days, rate } = req.body;
    try {
        const user = await pool.query('SELECT pft_balance FROM users WHERE id = $1', [req.userId]);
        if (user.rows[0].pft_balance < amount) return res.status(400).json({ message: "Số dư PFT không đủ" });

        await pool.query('BEGIN');
        await pool.query('UPDATE users SET pft_balance = pft_balance - $1 WHERE id = $2', [amount, req.userId]);
        await pool.query('INSERT INTO transactions (user_id, type, amount, status) VALUES ($1, $2, $3, $4)',
            [req.userId, 'STAKING', -amount, 'SUCCESS']);
        await pool.query('COMMIT');
        res.json({ message: "Gửi lãi thành công" });
    } catch (e) {
        await pool.query('ROLLBACK');
        res.status(500).json({ message: "Lỗi giao dịch" });
    }
});

// --- MINING ---
app.get('/api/mining/status', authUser, async (req, res) => {
    try {
        const user = await pool.query('SELECT total_investment, mining_balance, last_claim, pft_balance FROM users WHERE id = $1', [req.userId]);
        const u = user.rows[0];

        const lastTime = u.last_claim ? new Date(u.last_claim) : new Date();
        const now = new Date();
        const secondsPassed = (now - lastTime) / 1000;

        const PFT_PRICE = 0.1;
        const dailySpeedFromInvestment = (parseFloat(u.total_investment) * 0.075) / PFT_PRICE;
        const totalDailySpeed = 0.1 + dailySpeedFromInvestment;

        const earnings = (totalDailySpeed / 86400) * secondsPassed;

        await pool.query('UPDATE users SET pft_balance = pft_balance + $1, mining_balance = 0, last_claim = NOW() WHERE id = $2', [earnings, req.userId]);

        const updatedUser = await pool.query('SELECT pft_balance FROM users WHERE id = $1', [req.userId]);

        res.json({
            pft_balance: updatedUser.rows[0].pft_balance,
            daily_speed: totalDailySpeed
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: "Lỗi mining" });
    }
});

app.post('/api/mining/claim', authUser, async (req, res) => {
    try {
        const user = await pool.query('SELECT mining_balance, last_claim, total_investment, pft_balance FROM users WHERE id = $1', [req.userId]);
        const u = user.rows[0];

        const lastTime = u.last_claim ? new Date(u.last_claim) : new Date();
        const now = new Date();
        const secondsPassed = (now - lastTime) / 1000;

        const PFT_PRICE = 0.1;
        const dailySpeedFromInvestment = (parseFloat(u.total_investment) * 0.075) / PFT_PRICE;
        const totalDailySpeed = 0.1 + dailySpeedFromInvestment;

        const earnings = (totalDailySpeed / 86400) * secondsPassed;

        await pool.query('UPDATE users SET pft_balance = pft_balance + $1, mining_balance = 0, last_claim = NOW() WHERE id = $2', [earnings, req.userId]);

        res.json({ message: "Nhận thành công", claimed: earnings });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: "Lỗi claim mining" });
    }
});

app.post('/api/mining/buy', authUser, async (req, res) => {
    const { package_amount } = req.body;
    try {
        await pool.query('BEGIN');
        const user = await pool.query('SELECT usdt_balance FROM users WHERE id = $1', [req.userId]);

        if (user.rows[0].usdt_balance < package_amount) throw new Error("Không đủ USDT");

        await pool.query(
            'UPDATE users SET usdt_balance = usdt_balance - $1, total_investment = total_investment + $1 WHERE id = $2',
            [package_amount, req.userId]
        );

        const referrer = await pool.query('SELECT referred_by FROM users WHERE id = $1', [req.userId]);
        if (referrer.rows.length > 0 && referrer.rows[0].referred_by) {
            const refCode = referrer.rows[0].referred_by;
            const commAmount = package_amount * 0.1;

            await pool.query('UPDATE users SET usdt_balance = usdt_balance + $1 WHERE referral_code = $2', [commAmount, refCode]);
            await pool.query('INSERT INTO transactions (user_id, type, amount, status) VALUES ((SELECT id FROM users WHERE referral_code = $1), $2, $3, $4)',
                [refCode, 'AFFILIATE_COMMISSION', commAmount, 'SUCCESS']);
        }

        await pool.query('COMMIT');
        res.json({ message: "Mua máy đào thành công" });
    } catch (e) {
        await pool.query('ROLLBACK');
        res.status(400).json({ message: e.message });
    }
});

// --- P2P ---
app.get('/api/p2p/orders', authUser, async (req, res) => {
    try {
        const { type } = req.query;
        let query = 'SELECT * FROM p2p_orders';
        let params = [];
        if (type && type !== 'ALL') {
            query += ' WHERE type = $1';
            params.push(type);
        }
        const orders = await pool.query(query, params);
        res.json(orders.rows);
    } catch (e) { res.status(500).json({ message: "Lỗi tải đơn hàng P2P" }); }
});

app.post('/api/p2p/create-order', authUser, async (req, res) => {
    const { orderId, amount, type, userBank } = req.body;
    try {
        const orderRes = await pool.query('SELECT price FROM p2p_orders WHERE id = $1', [orderId]);
        if (orderRes.rows.length === 0) return res.status(404).json({ message: "Không tìm thấy đơn hàng" });

        const price = parseFloat(orderRes.rows[0].price);
        const amountUsdt = parseFloat(amount);
        const amountVnd = Math.round(amountUsdt * price);

        await pool.query(
            'INSERT INTO p2p_trades (order_id, user_id, amount, amount_vnd, user_bank_info, type, status) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [orderId, req.userId, amountUsdt, amountVnd, JSON.stringify(userBank), type, 'PENDING']
        );
        res.json({ message: "Lệnh đã gửi tới Admin" });
    } catch (e) {
        console.error("Error creating P2P order:", e);
        res.status(500).json({ message: "Lỗi gửi lệnh P2P" });
    }
});

// --- WEBHOOK SEPAY ---
async function handleSepayWebhook(req, res) {
    const { content, transferAmount, referenceCode } = req.body;

    try {
        console.log("Sepay Webhook Received:", req.body);

        if (!content || !transferAmount) {
            return res.status(200).json({ success: false, message: "Missing data" });
        }

        const uidMatch = content.match(/\d{6}/);
        if (!uidMatch) {
            return res.status(200).json({ success: false, message: "No UID found in content" });
        }

        const uid = parseInt(uidMatch[0]);
        const amountVnd = Math.round(parseFloat(transferAmount));

        await pool.query('BEGIN');

        const tradeRes = await pool.query(`
            SELECT pt.*, u.id as user_db_id
            FROM p2p_trades pt
            JOIN users u ON pt.user_id = u.id
            WHERE u.uid = $1 AND ROUND(pt.amount_vnd) = $2 AND pt.status = 'PENDING' AND pt.type = 'BUY'
            LIMIT 1
        `, [uid, amountVnd]);

        if (tradeRes.rows.length > 0) {
            const t = tradeRes.rows[0];

            await pool.query('UPDATE users SET usdt_balance = usdt_balance + $1 WHERE id = $2', [t.amount, t.user_db_id]);
            await pool.query('UPDATE p2p_trades SET status = \'SUCCESS\', admin_note = $1 WHERE id = $2',
                [`Auto-approved by Sepay (Ref: ${referenceCode || 'N/A'})`, t.id]);
            await pool.query('INSERT INTO transactions (user_id, type, amount, status, address) VALUES ($1, $2, $3, $4, $5)',
                [t.user_db_id, 'NAP', t.amount, 'SUCCESS', 'P2P Buy (Sepay Auto)']);

            await pool.query('COMMIT');
            console.log(`Successfully auto-approved trade ID ${t.id} for UID ${uid}`);
            return res.json({ success: true, message: "Auto-approved trade " + t.id });
        } else {
            await pool.query('ROLLBACK');
            return res.status(200).json({ success: false, message: "No matching pending trade found" });
        }
    } catch (e) {
        try { await pool.query('ROLLBACK'); } catch (re) {}
        console.error("Sepay Webhook Critical Error:", e);
        res.status(500).json({ success: false, error: e.message });
    }
}

app.post('/api/webhook/sepay', handleSepayWebhook);
app.post('/admin.html', handleSepayWebhook);

// --- AFFILIATE ---
app.get('/api/user/affiliate-stats', authUser, async (req, res) => {
    try {
        const user = await pool.query('SELECT referral_code FROM users WHERE id = $1', [req.userId]);
        const refCode = user.rows[0].referral_code;

        const team = await pool.query('SELECT uid, email, fullname, total_investment, created_at FROM users WHERE referred_by = $1 ORDER BY created_at DESC', [refCode]);

        const comms = await pool.query('SELECT SUM(amount) as total FROM transactions WHERE user_id = $1 AND type = \'AFFILIATE_COMMISSION\'', [req.userId]);

        res.json({
            team: team.rows,
            total_commission: parseFloat(comms.rows[0].total || 0),
            referral_code: refCode
        });
    } catch (e) { res.status(500).json({ message: "Lỗi" }); }
});

// --- ADMIN ---
app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await pool.query('SELECT id, uid, email, usdt_balance, pft_balance, assigned_wallet, kyc_status FROM users ORDER BY id DESC');
        res.json(users.rows);
    } catch (e) { res.status(500).json({ message: "Lỗi tải danh sách" }); }
});

app.post('/api/admin/buff', async (req, res) => {
    const { uid, amount, asset } = req.body;
    const col = asset === 'pft' ? 'pft_balance' : 'usdt_balance';
    const amt = parseFloat(amount);
    try {
        await pool.query('BEGIN');
        await pool.query(`UPDATE users SET ${col} = ${col} + $1 WHERE uid = $2`, [amt, uid]);
        await pool.query('INSERT INTO transactions (user_id, type, amount, status, address) VALUES ((SELECT id FROM users WHERE uid = $1), $2, $3, $4, $5)',
            [uid, 'NAP', amt, 'SUCCESS', 'Admin Buff']);
        await pool.query('COMMIT');
        res.json({ message: "Buff thành công" });
    } catch (e) {
        await pool.query('ROLLBACK');
        res.status(500).json({ message: "Lỗi buff tiền" });
    }
});

app.post('/api/admin/set-wallet', async (req, res) => {
    const { uid, wallet } = req.body;
    try {
        await pool.query('UPDATE users SET assigned_wallet = $1 WHERE uid = $2', [wallet, uid]);
        await pool.query('UPDATE wallet_requests SET status = \'SUCCESS\' WHERE user_id = (SELECT id FROM users WHERE uid = $1)', [uid]);
        res.json({ message: "Cập nhật thành công" });
    } catch (e) { res.status(500).json({ message: "Lỗi" }); }
});

app.post('/api/admin/p2p-create', async (req, res) => {
    const { type, price, stock, merchant, bank_info } = req.body;
    try {
        await pool.query(
            'INSERT INTO p2p_orders (type, price, stock, merchant_name, bank_info) VALUES ($1, $2, $3, $4, $5)',
            [type, price, stock, merchant, bank_info]
        );
        res.json({ message: "Đã đăng đơn P2P" });
    } catch (e) { res.status(500).json({ message: "Lỗi tạo đơn" }); }
});

app.get('/api/admin/p2p-trades', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT pt.*, u.uid, u.email, po.merchant_name
            FROM p2p_trades pt
            JOIN users u ON pt.user_id = u.id
            LEFT JOIN p2p_orders po ON pt.order_id = po.id
            ORDER BY pt.created_at DESC
        `);
        res.json(result.rows);
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: "Lỗi tải giao dịch P2P" });
    }
});

app.post('/api/admin/p2p-trade-action', async (req, res) => {
    const { id, action } = req.body;
    try {
        await pool.query('BEGIN');
        const tradeRes = await pool.query('SELECT * FROM p2p_trades WHERE id = $1', [id]);
        if (tradeRes.rows.length === 0) throw new Error("Giao dịch không tồn tại");
        const t = tradeRes.rows[0];

        if (t.status !== 'PENDING') throw new Error("Giao dịch đã được xử lý");

        if (action === 'APPROVE') {
            if (t.type === 'BUY') {
                await pool.query('UPDATE users SET usdt_balance = usdt_balance + $1 WHERE id = $2', [t.amount, t.user_id]);
            } else if (t.type === 'SELL') {
                const userRes = await pool.query('SELECT usdt_balance FROM users WHERE id = $1', [t.user_id]);
                if (userRes.rows[0].usdt_balance < t.amount) throw new Error("Người dùng không đủ số dư để bán");
                await pool.query('UPDATE users SET usdt_balance = usdt_balance - $1 WHERE id = $2', [t.amount, t.user_id]);
            }
            await pool.query('UPDATE p2p_trades SET status = \'SUCCESS\' WHERE id = $1', [id]);
        } else {
            await pool.query('UPDATE p2p_trades SET status = \'CANCELLED\' WHERE id = $1', [id]);
        }

        await pool.query('COMMIT');
        res.json({ message: "Cập nhật thành công" });
    } catch (e) {
        await pool.query('ROLLBACK');
        res.status(400).json({ message: e.message });
    }
});

app.get('/api/admin/deposit-requests', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT wr.*, u.uid, u.email
            FROM wallet_requests wr
            JOIN users u ON wr.user_id = u.id
            WHERE wr.status = 'PENDING'
            ORDER BY wr.created_at DESC
        `);
        res.json(result.rows);
    } catch (e) { res.status(500).json({ message: "Lỗi tải yêu cầu" }); }
});

app.get('/api/admin/withdraw-requests', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT t.*, u.uid
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            WHERE t.type = 'RUT' AND t.status = 'PENDING'
            ORDER BY t.created_at DESC
        `);
        res.json(result.rows);
    } catch (e) { res.status(500).json({ message: "Lỗi tải yêu cầu" }); }
});

app.post('/api/admin/withdraw-action', async (req, res) => {
    const { id, status } = req.body;
    try {
        await pool.query('UPDATE transactions SET status = $1 WHERE id = $2', [status, id]);
        res.json({ message: "Đã cập nhật trạng thái" });
    } catch (e) { res.status(500).json({ message: "Lỗi xử lý" }); }
});

app.post('/api/admin/p2p-delete', async (req, res) => {
    const { id } = req.body;
    try {
        await pool.query('DELETE FROM p2p_orders WHERE id = $1', [id]);
        res.json({ message: "Đã xóa đơn hàng" });
    } catch (e) { res.status(500).json({ message: "Lỗi khi xóa" }); }
});

// Export for Netlify Functions
module.exports = app;

// Start server only when run directly (local development)
if (require.main === module) {
    app.listen(5000, '0.0.0.0', () => console.log('PolyFinance Server is Live on Port 5000'));
}
