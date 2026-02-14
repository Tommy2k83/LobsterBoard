const crypto = require('crypto');

module.exports = function(ctx) {
  function readData() {
    try {
      return ctx.readData('notes.json');
    } catch {
      return { notes: [], categories: ['General', 'Work', 'Tech', 'Ideas', 'Personal'] };
    }
  }

  function writeData(data) {
    ctx.writeData('notes.json', data);
  }

  return {
    routes: {
      'GET /': (req, res, { query }) => {
        const data = readData();
        let notes = data.notes || [];
        if (query.q) {
          const lower = query.q.toLowerCase();
          notes = notes.filter(n => (n.title || '').toLowerCase().includes(lower) || (n.body || '').toLowerCase().includes(lower));
        }
        if (query.tag) notes = notes.filter(n => (n.tags || []).includes(query.tag));
        if (query.category) notes = notes.filter(n => n.category === query.category);
        notes.sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || new Date(b.updatedAt) - new Date(a.updatedAt));
        return notes;
      },

      'GET /tags': (req, res, { query }) => {
        const data = readData();
        const counts = {};
        data.notes.forEach(n => (n.tags || []).forEach(t => { counts[t] = (counts[t] || 0) + 1; }));
        return counts;
      },

      'GET /categories': (req, res, { query }) => {
        const data = readData();
        return data.categories || [];
      },

      'GET /:id': (req, res, { params }) => {
        const data = readData();
        const note = data.notes.find(n => n.id === params.id);
        if (!note) { res.statusCode = 404; return { error: 'Not found' }; }
        return note;
      },

      'POST /': (req, res, { body }) => {
        const data = readData();
        const now = new Date().toISOString();
        const note = {
          id: crypto.randomUUID(),
          title: body.title || 'Untitled',
          body: body.body || '',
          tags: body.tags || [],
          category: body.category || 'General',
          pinned: body.pinned || false,
          createdAt: now,
          updatedAt: now
        };
        data.notes.push(note);
        writeData(data);
        res.statusCode = 201;
        return note;
      },

      'PATCH /:id': (req, res, { body, params }) => {
        const data = readData();
        const idx = data.notes.findIndex(n => n.id === params.id);
        if (idx === -1) { res.statusCode = 404; return { error: 'Not found' }; }
        const allowed = ['title', 'body', 'tags', 'category', 'pinned'];
        allowed.forEach(k => { if (body[k] !== undefined) data.notes[idx][k] = body[k]; });
        data.notes[idx].updatedAt = new Date().toISOString();
        writeData(data);
        return data.notes[idx];
      },

      'DELETE /:id': (req, res, { params }) => {
        const data = readData();
        const idx = data.notes.findIndex(n => n.id === params.id);
        if (idx === -1) { res.statusCode = 404; return { error: 'Not found' }; }
        data.notes.splice(idx, 1);
        writeData(data);
        return { ok: true };
      }
    }
  };
};
