import { Hono } from 'hono';
import { sendCodeEmail } from './email';
import { SignJWT } from 'jose';
async function sign(payload, secret) {
	return await new SignJWT(payload).setProtectedHeader({ alg: 'HS256' }).sign(new TextEncoder().encode(secret));
}
const app = new Hono();

/* ======== CORS ======== */
app.use('*', async (c, next) => {
	c.header('Access-Control-Allow-Origin', '*');
	c.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
	c.header('Access-Control-Allow-Headers', 'Content-Type');
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

// 想加第三张表？复制上面一行，改表名和字段数组即可

/* ======== 邮箱验证码登录 ======== */
app.post('/api/login/code', async (c) => {
	const { email } = await c.req.json();
	if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
		return c.json({ code: 400, message: '邮箱格式错误' }, 400);
	}
	const code = String(Math.random()).slice(-6); // 6 位数字
	await sendCodeEmail(email, code, c.env); // 发信
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

export default app;
