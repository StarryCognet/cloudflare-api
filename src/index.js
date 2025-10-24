import { Hono } from 'hono';
const app = new Hono();

/* ========== 统一响应格式 ========== */
function ok(c, data, msg = 'success') {
  return c.json({ code: 200, message: msg, data }, 200);
}
function created(c, data, msg = 'created') {
  return c.json({ code: 201, message: msg, data }, 201);
}
function bad(c, msg = 'bad request') {
  return c.json({ code: 400, message: msg, data: null }, 400);
}
function notFound(c, msg = 'not found') {
  return c.json({ code: 404, message: msg, data: null }, 404);
}

/* ----------  旧 /posts 接口（原样搬家） ---------- */
app.get('/posts', async (c) => {
	const { results } = await c.env.learn_db.prepare('SELECT * FROM posts').all();
	return c.json(results);
});

app.post('/posts', async (c) => {
	const { title, body: content } = await c.req.json();
	if (!title || !content) return c.json({ error: 'title & body required' }, 400);
	const { meta } = await c.env.learn_db.prepare('INSERT INTO posts (title, body) VALUES (?, ?)').bind(title, content).run();
	return c.json({ id: meta.last_row_id, title, body: content }, 201);
});

app.put('/posts', async (c) => {
	const id = Number(c.req.query('id'));
	if (!id) return c.json({ error: '缺少 ?id=' }, 400);
	const { title, body: content } = await c.req.json();
	if (!title || !content) return c.json({ error: 'title & body required' }, 400);
	const info = await c.env.learn_db.prepare('UPDATE posts SET title = ?, body = ? WHERE id = ?').bind(title, content, id).run();
	if (info.meta.changes === 0) return c.json({ error: 'id 不存在' }, 404);
	return c.json({ id, title, body: content });
});

app.delete('/posts', async (c) => {
	const id = Number(c.req.query('id'));
	if (!id) return c.json({ error: '缺少 ?id=' }, 400);
	const info = await c.env.learn_db.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();
	if (info.meta.changes === 0) return c.json({ error: 'id 不存在' }, 404);
	return c.json({ message: '已删除' });
});

/* ----------  新表 /api/products/* 待会在这加  ---------- */

/* ====================  products 表  ==================== */
// 查
app.get("/api/products/get", async c => {
  const { results } = await c.env.learn_db.prepare("SELECT * FROM products ORDER BY id DESC").all();
  return ok(c, results);                 // 200
});

// 增
app.post("/api/products/add", async c => {
  const { name, price } = await c.req.json();
  if (!name || price == null) return bad(c, "name & price 必填");
  const { meta } = await c.env.learn_db.prepare("INSERT INTO products (name, price) VALUES (?, ?)").bind(name, price).run();
  return created(c, { id: meta.last_row_id }, "创建成功"); // 201
});

// 改
app.post("/api/products/update", async c => {
  const { id, name, price } = await c.req.json();
  if (!id || !name || price == null) return bad(c, "id & name & price 必填");
  const info = await c.env.learn_db.prepare("UPDATE products SET name = ?, price = ? WHERE id = ?").bind(name, price, id).run();
  if (info.meta.changes === 0) return notFound(c, "id 不存在");
  return ok(c, null, "更新成功");        // 200
});

// 删
app.post("/api/products/del", async c => {
  const { id } = await c.req.json();
  if (!id) return bad(c, "id 必填");
  const info = await c.env.learn_db.prepare("DELETE FROM products WHERE id = ?").bind(id).run();
  if (info.meta.changes === 0) return notFound(c, "id 不存在");
  return ok(c, null, "删除成功");        // 200
});

export default app;
