import { Hono } from 'hono';
const app = new Hono();

/* ========== 统一响应工具 ========== */
const ok = (c, data = null, msg = 'success') => c.json({ code: 200, message: msg, data }, 200);
const created = (c, data = null, msg = 'created') => c.json({ code: 201, message: msg, data }, 201);
const bad = (c, msg = 'bad request') => c.json({ code: 400, message: msg, data: null }, 400);
const notFound = (c, msg = 'not found') => c.json({ code: 404, message: msg, data: null }, 404);

/* ==========================================================
 *  模板：一张表四套路由
 *  以后复制这块，把表名/字段换一下即可
 * ========================================================== */
function registerCrud(app, table, fields) {
	const [f1, f2] = fields; // 只演示两个字段，够用
	/* ---- 查 ---- */
	app.get(`/api/${table}/get`, async (c) => {
		const { results } = await c.env.learn_db.prepare(`SELECT * FROM ${table} ORDER BY id DESC`).all();
		return ok(c, results);
	});
	/* ---- 增 ---- */
	app.post(`/api/${table}/add`, async (c) => {
		const body = await c.req.json();
		if (!body[f1] || body[f2] == null) return bad(c, `${f1} & ${f2} 必填`);
		const { meta } = await c.env.learn_db.prepare(`INSERT INTO ${table} (${f1}, ${f2}) VALUES (?, ?)`).bind(body[f1], body[f2]).run();
		return created(c, { id: meta.last_row_id }, '创建成功');
	});
	/* ---- 改 ---- */
	app.post(`/api/${table}/update`, async (c) => {
		const { id, ...rest } = await c.req.json();
		if (!id || !rest[f1] || rest[f2] == null) return bad(c, 'id & 字段必填');
		const info = await c.env.learn_db.prepare(`UPDATE ${table} SET ${f1} = ?, ${f2} = ? WHERE id = ?`).bind(rest[f1], rest[f2], id).run();
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

/* ====================  注册两张表  ==================== */
registerCrud(app, 'posts', ['title', 'body']); // 旧表
registerCrud(app, 'products', ['name', 'price']); // 新表

export default app;
