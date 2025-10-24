import { Hono } from 'hono';
const app = new Hono();

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
  return c.json(results, 200);          // 200 OK
});

// 增
app.post("/api/products/add", async c => {
  const { name, price } = await c.req.json();
  if (!name || price == null) return c.json({ message: "name & price 必填" }, 400);
  const { meta } = await c.env.learn_db.prepare("INSERT INTO products (name, price) VALUES (?, ?)").bind(name, price).run();
  return c.json({ message: "创建成功", id: meta.last_row_id }, 201); // 201 Created
});

// 改
app.post("/api/products/update", async c => {
  const { id, name, price } = await c.req.json();
  if (!id || !name || price == null) return c.json({ message: "id & name & price 必填" }, 400);
  const info = await c.env.learn_db.prepare("UPDATE products SET name = ?, price = ? WHERE id = ?").bind(name, price, id).run();
  if (info.meta.changes === 0) return c.json({ message: "id 不存在" }, 404);
  return c.json({ message: "更新成功" }, 200);
});

// 删
app.post("/api/products/del", async c => {
  const { id } = await c.req.json();
  if (!id) return c.json({ message: "id 必填" }, 400);
  const info = await c.env.learn_db.prepare("DELETE FROM products WHERE id = ?").bind(id).run();
  if (info.meta.changes === 0) return c.json({ message: "id 不存在" }, 404);
  return c.json({ message: "删除成功" }, 200);
});

export default app;
