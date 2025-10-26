import { Hono } from 'hono';
import { sendCodeEmail } from './email';
import { SignJWT, jwtVerify } from 'jose';
async function sign(payload, secret) {
	return await new SignJWT(payload).setProtectedHeader({ alg: 'HS256' }).sign(new TextEncoder().encode(secret));
}

async function verify(token, secret) {
	try {
		const { payload } = await jwtVerify(token, new TextEncoder().encode(secret));
		return payload;
	} catch (e) {
		return null;
	}
}

const app = new Hono();

/* ======== CORS ======== */
app.use('*', async (c, next) => {
	c.header('Access-Control-Allow-Origin', '*');
	c.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
	c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
	if (c.req.method === 'OPTIONS') return c.text('', 204); // 预检直接空响应
	await next();
});

/* ======== 统一响应 ======== */
const ok = (c, data = null, msg = '成功') => c.json({ code: 200, message: msg, data }, 200);
const created = (c, data = null, msg = 'created') => c.json({ code: 201, message: msg, data }, 201);
const bad = (c, msg = 'bad request') => c.json({ code: 400, message: msg, data: null }, 400);
const notFound = (c, msg = 'not found') => c.json({ code: 404, message: msg, data: null }, 404);

/* ==========================================================
 *  终极模板：任意字段、任意校验
 *  字段描述 = { name: 字段名, required?: bool, validate?: (v)=>bool }
 *  示例见底部
 * ========================================================== */
function registerCrud(app, table, fields) {
	const fieldNames = fields.map((f) => f.name); // ['name','price']
	const marks = fieldNames.map((_) => '?').join(','); // ?,?

	/* ---- 查 ---- */
	app.get(`/api/${table}/get`, async (c) => {
		const { results } = await c.env.learn_db.prepare(`SELECT * FROM ${table} ORDER BY id DESC`).all();
		return ok(c, results);
	});

	/* ---- 增 ---- */
	app.post(`/api/${table}/add`, async (c) => {
		const body = await c.req.json();
		// 通用校验
		for (const f of fields) {
			const v = body[f.name];
			if (f.required && (v === undefined || v === null)) return bad(c, `${f.name} 必填`);
			if (f.validate && !f.validate(v)) return bad(c, `${f.name} 格式非法`);
		}
		const { meta } = await c.env.learn_db
			.prepare(`INSERT INTO ${table} (${fieldNames.join(',')}) VALUES (${marks})`)
			.bind(...fieldNames.map((n) => body[n]))
			.run();
		return created(c, { id: meta.last_row_id }, '添加成功');
	});

	/* ---- 改 ---- */
	app.post(`/api/${table}/update`, async (c) => {
		const body = await c.req.json();
		if (!body.id) return bad(c, 'id 必填');
		// 动态拼 SET 子句
		const setClause = [];
		const values = [];
		for (const f of fields) {
			if (body[f.name] !== undefined) {
				setClause.push(`${f.name} = ?`);
				values.push(body[f.name]);
			}
		}
		if (setClause.length === 0) return bad(c, '无更新字段');
		values.push(body.id);
		const info = await c.env.learn_db
			.prepare(`UPDATE ${table} SET ${setClause.join(',')} WHERE id = ?`)
			.bind(...values)
			.run();
		if (info.meta.changes === 0) return notFound(c, 'id 不存在');
		return ok(c, null, '更新成功');
	});

	/* ---- 删 ---- */
	app.post(`/api/${table}/del`, async (c) => {
		const { id } = await c.req.json();
		if (!id) return bad(c, 'id 必填');
		const info = await c.env.learn_db.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(id).run();
		if (info.meta.changes === 0) return notFound(c, 'id 不存在');
		return ok(c, null, '删除成功');
	});
}

/* ====================  注册表（只改这里！） ==================== */
registerCrud(app, 'posts', [
	{ name: 'title', required: true },
	{ name: 'body', required: true },
]);

registerCrud(app, 'products', [
	{ name: 'name', required: true, validate: (v) => typeof v === 'string' && v.length > 0 },
	{ name: 'price', required: true, validate: (v) => typeof v === 'number' && v >= 0 },
]);

registerCrud(app, 'messages', [
	{ name: 'user', required: true, validate: (v) => typeof v === 'string' && v.length <= 20 },
	{ name: 'msg', required: true, validate: (v) => typeof v === 'string' && v.length <= 500 },
	{ name: 'likes', required: false, validate: (v) => Number.isInteger(v) && v >= 0 },
	{ name: 'created_at', required: true, validate: (v) => typeof v === 'number' },
]);

/* ==========================================================
 * 用户表（可插拔字段）
 * 以后加字段：1. 数据库 ALTER TABLE  2. 在下面数组里加一项
 * ========================================================== */
registerCrud(app, 'users', [
	{ name: 'username', required: true, validate: (v) => typeof v === 'string' && v.length >= 3 && v.length <= 20 },
	{ name: 'password', required: true, validate: (v) => typeof v === 'string' && v.length >= 6 },
	{ name: 'email', required: true, validate: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) },
	{ name: 'phone', required: false, validate: (v) => v == null || /^\d{7,15}$/.test(v) },
	{ name: 'role', required: false, validate: (v) => !v || ['user', 'admin', 'vip'].includes(v) },
	{ name: 'created_at', required: true, validate: (v) => Number.isInteger(v) },
	{ name: 'updated_at', required: true, validate: (v) => Number.isInteger(v) },
]);

// 想加第三张表？复制上面一行，改表名和字段数组即可

/* ======== 邮箱验证码登录 ======== */
app.post('/api/login/code', async (c) => {
	const { email } = await c.req.json();
	if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
		return c.json({ code: 400, message: '邮箱格式错误' }, 400);
	}
	const code = String(Math.random()).slice(-6); // 6 位数字
	await sendCodeEmail(email, code); // 发信
	// 把 code 写入 D1 表 email_codes，5 min 后过期
	const expire = Date.now() + 300_000;
	await c.env.learn_db.prepare(`INSERT OR REPLACE INTO email_codes(email,code,expire_at) VALUES (?,?,?)`).bind(email, code, expire).run();
	return c.json({ code: 200, message: '验证码已发送' }, 200);
});

/* ======== 校验验证码 + 颁发 JWT ======== */
app.post('/api/login/verify', async (c) => {
	const { email, code } = await c.req.json();
	if (!email || !code) return c.json({ code: 400, message: '邮箱和验证码必填' }, 400);

	// 1. 取库里的验证码
	const row = await c.env.learn_db.prepare('SELECT code, expire_at FROM email_codes WHERE email = ?').bind(email).first();
	if (!row || Date.now() > row.expire_at || row.code !== code) {
		return c.json({ code: 400, message: '验证码错误或已过期' }, 400);
	}

	// 2. 验证成功，删码防复用
	await c.env.learn_db.prepare('DELETE FROM email_codes WHERE email = ?').bind(email).run();

	// 3. 生成 JWT（有效期 7 天）
	const jwt = await sign({ email, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600 }, c.env.JWT_SECRET);

	return c.json({ code: 200, message: '登录成功', data: { jwt } }, 200);
});

app.post('/api/auth/register', async (c) => {
	const body = await c.req.json();
	// 1. 基本校验
	if (!body.username || !body.password || !body.email) return bad(c, '用户名、密码、邮箱必填');
	if (body.username.length < 3 || body.username.length > 20) return bad(c, '用户名 3-20 位');
	if (body.password.length < 6) return bad(c, '密码至少 6 位');
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) return bad(c, '邮箱格式错误');

	// 2. 密码哈希（bcrypt 需要 npm i bcryptjs + nodejs_compat）
	const bcrypt = await import('bcryptjs');
	const hashed = await bcrypt.default.hash(body.password, 10);

	// 3. 防重
	const existU = await c.env.learn_db.prepare('SELECT id FROM users WHERE username=?').bind(body.username).first();
	if (existU) return bad(c, '用户名已存在');
	const existE = await c.env.learn_db.prepare('SELECT id FROM users WHERE email=?').bind(body.email).first();
	if (existE) return bad(c, '邮箱已注册');

	// 4. 写入
	const now = Date.now();
	const { meta } = await c.env.learn_db
		.prepare(
			`
    INSERT INTO users(username,password,email,phone,role,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?)`
		)
		.bind(body.username, hashed, body.email, body.phone || null, body.role || 'user', now, now)
		.run();

	return created(c, { id: meta.last_row_id }, '注册成功');
});

app.post('/api/auth/login', async (c) => {
	const { username, password } = await c.req.json();
	if (!username || !password) return bad(c, '用户名和密码必填');

	// 1. 查用户
	const user = await c.env.learn_db.prepare('SELECT id,password,email,role FROM users WHERE username=?').bind(username).first();
	if (!user) return bad(c, '用户不存在或密码错误');

	// 2. 验密码
	const bcrypt = await import('bcryptjs');
	const isValid = await bcrypt.default.compare(password, user.password);
	if (!isValid) return bad(c, '用户不存在或密码错误');

	// 3. 颁发 JWT（7 天）和刷新令牌（30 天）
	const jwt = await sign(
		{ uid: user.id, email: user.email, role: user.role, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600 },
		c.env.JWT_SECRET
	);
	
	// 检查 REFRESH_TOKEN_SECRET 是否存在
	let refreshToken = null;
	if (c.env.REFRESH_TOKEN_SECRET) {
		refreshToken = await sign(
			{ uid: user.id, email: user.email, role: user.role, exp: Math.floor(Date.now() / 1000) + 30 * 24 * 3600 },
			c.env.REFRESH_TOKEN_SECRET
		);
	}

	// 确认 JWT 值
	console.log('JWT:', jwt);

	return ok(c, { jwt, refreshToken, username, email: user.email, role: user.role }, '登录成功');
});

/* ========== 刷新令牌 ========== */
app.post('/api/auth/refresh', async (c) => {
  // 优先从请求头获取，其次从请求体获取
  let refreshToken = c.req.header('Refresh-Token');
  
  // 如果请求头中没有，则尝试从请求体获取
  if (!refreshToken) {
    try {
      const body = await c.req.json();
      refreshToken = body.refreshToken;
    } catch (e) {
      // 解析JSON失败，保持refreshToken为null
    }
  }
  
  if (!refreshToken) return c.json({ code: 401, message: '未提供刷新令牌' }, 401);

  // 检查 REFRESH_TOKEN_SECRET 是否存在
  if (!c.env.REFRESH_TOKEN_SECRET) {
    return c.json({ code: 500, message: '服务器未配置刷新令牌密钥' }, 500);
  }

  try {
    const payload = await verify(refreshToken, c.env.REFRESH_TOKEN_SECRET);
    if (!payload || !payload.uid) return c.json({ code: 401, message: '刷新令牌无效' }, 401);

    // 重新颁发 JWT
    const jwt = await sign(
      { uid: payload.uid, email: payload.email, role: payload.role, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600 },
      c.env.JWT_SECRET
    );
    return ok(c, { jwt }, '刷新成功');
  } catch (e) {
    return c.json({ code: 401, message: '刷新令牌无效或过期' }, 401);
  }
});

// 放在需要登录的路由之前
app.use('/api/protected/*', async (c, next) => {
  const hdr = c.req.header('Authorization');
  if (!hdr || !hdr.startsWith('Bearer ')) return c.json({ code: 401, message: '未登录' }, 401);
  const token = hdr.slice(7);
  try {
    const payload = await verify(token, c.env.JWT_SECRET);
    if (!payload || !payload.uid) return c.json({ code: 401, message: 'Token 无效' }, 401);
    c.set('jwtPayload', payload);
    await next();
  } catch (e) {
    return c.json({ code: 401, message: 'Token 无效或过期' }, 401);
  }
});

/* ========== 个人资料（兼容 URL token） ========== */
app.get('/api/me', async (c) => {
  // ① 优先读 Headers，其次读 URL 参数
  let token = c.req.header('Authorization')?.slice(7);          // Bearer <jwt>
  if (!token) token = c.req.query('token');                     // ?token=<jwt>
  if (!token) return c.json({ code: 401, message: '未登录' }, 401);

  const payload = await verify(token, c.env.JWT_SECRET);
  if (!payload || !payload.uid) return c.json({ code: 401, message: 'Token 无效' }, 401);

  const user = await c.env.learn_db
    .prepare('SELECT id, username, email, phone, role, created_at, updated_at FROM users WHERE id = ?')
    .bind(payload.uid)
    .first();

  if (!user) return c.json({ code: 404, message: '用户不存在' }, 404);
  return ok(c, user);
});

/* ========== 忘记密码：发送验证码 ========== */
app.post('/api/auth/forgot-password', async (c) => {
  const { email } = await c.req.json();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return c.json({ code: 400, message: '邮箱格式错误' }, 400);
  }

  const code = String(Math.random()).slice(-6); // 6 位数字
  await sendCodeEmail(email, code); // 发信
  const expire = Date.now() + 300_000;
  await c.env.learn_db.prepare(`INSERT OR REPLACE INTO email_codes(email,code,expire_at) VALUES (?,?,?)`).bind(email, code, expire).run();
  return c.json({ code: 200, message: '验证码已发送' }, 200);
});

/* ========== 重置密码 ========== */
app.post('/api/auth/reset-password', async (c) => {
  const { email, code, newPassword } = await c.req.json();
  if (!email || !code || !newPassword) return c.json({ code: 400, message: '邮箱、验证码、新密码必填' }, 400);

  // 1. 校验验证码
  const row = await c.env.learn_db.prepare('SELECT code, expire_at FROM email_codes WHERE email = ?').bind(email).first();
  if (!row || Date.now() > row.expire_at || row.code !== code) {
    return c.json({ code: 400, message: '验证码错误或已过期' }, 400);
  }

  // 2. 验证成功，删码防复用
  await c.env.learn_db.prepare('DELETE FROM email_codes WHERE email = ?').bind(email).run();

  // 3. 更新密码
  const bcrypt = await import('bcryptjs');
  const hashed = await bcrypt.default.hash(newPassword, 10);
  await c.env.learn_db.prepare(`UPDATE users SET password = ? WHERE email = ?`).bind(hashed, email).run();

  return c.json({ code: 200, message: '密码重置成功' }, 200);
});

/* ========== 修改个人资料（头像、邮箱、密码） ========== */
app.post('/api/me/update', async (c) => {
  const token = c.req.header('Authorization')?.slice(7); // Bearer <JWT>
  if (!token) return c.json({ code: 401, message: '未登录' }, 401);

  try {
    const payload = await verify(token, c.env.JWT_SECRET);
    if (!payload || !payload.uid) return c.json({ code: 401, message: 'Token 无效' }, 401);

    const body = await c.req.json();
    
    // 构建更新语句
    const updates = [];
    const values = [];
    
    if (body.username !== undefined) {
      updates.push('username = ?');
      values.push(body.username);
    }
    
    if (body.password !== undefined) {
      const bcrypt = await import('bcryptjs');
      const hashed = await bcrypt.default.hash(body.password, 10);
      updates.push('password = ?');
      values.push(hashed);
    }
    
    if (body.email !== undefined) {
      updates.push('email = ?');
      values.push(body.email);
    }
    
    if (body.phone !== undefined) {
      updates.push('phone = ?');
      values.push(body.phone);
    }
    
    if (body.role !== undefined) {
      updates.push('role = ?');
      values.push(body.role);
    }
    
    // 更新时间
    updates.push('updated_at = ?');
    values.push(Date.now());
    values.push(payload.uid); // WHERE 条件

    if (updates.length === 2) { // 只有updated_at和uid
      return c.json({ code: 400, message: '没有提供可更新的字段' }, 400);
    }

    await c.env.learn_db.prepare(`
      UPDATE users
      SET ${updates.join(', ')}
      WHERE id = ?
    `).bind(...values).run();

    return c.json({ code: 200, message: '资料更新成功' }, 200);
  } catch (e) {
    return c.json({ code: 401, message: 'Token 无效或过期' }, 401);
  }
});

export default app;
