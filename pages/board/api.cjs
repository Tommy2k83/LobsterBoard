module.exports = function(ctx) {
  function readBoard() {
    try {
      return ctx.readData('board.json');
    } catch {
      return { id: 'root', title: 'Project Board', type: 'category', icon: '📋', children: [], comments: [] };
    }
  }

  function writeBoard(data) {
    ctx.writeData('board.json', data);
  }

  function slugify(str) {
    return str.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  }

  function findByPath(root, segments) {
    let node = root;
    for (const seg of segments) {
      if (!node.children) return null;
      const child = node.children.find(c => c.id === seg || slugify(c.title) === seg);
      if (!child) return null;
      node = child;
    }
    return node;
  }

  return {
    routes: {
      'GET /': (req, res, { query }) => {
        return readBoard();
      },

      'POST /items': (req, res, { body }) => {
        const board = readBoard();
        const now = new Date().toISOString();
        const title = body.title || 'Untitled';
        const newItem = {
          id: body.id || slugify(title),
          title,
          type: body.type || 'item',
          status: body.status || 'backlog',
          icon: body.icon || '📄',
          children: [],
          comments: [],
          createdAt: now,
          updatedAt: now
        };
        if (!board.children) board.children = [];
        board.children.push(newItem);
        board.updatedAt = now;
        writeBoard(board);
        res.statusCode = 201;
        return newItem;
      },

      'GET /*': (req, res, { params }) => {
        const board = readBoard();
        const segments = params['*'].split('/').filter(Boolean);
        const node = findByPath(board, segments);
        if (!node) { res.statusCode = 404; return { error: 'Not found' }; }
        return node;
      },

      'POST /*/items': (req, res, { body, params }) => {
        const board = readBoard();
        const segments = params['*'].split('/').filter(Boolean);
        const parent = findByPath(board, segments);
        if (!parent) { res.statusCode = 404; return { error: 'Path not found' }; }
        const now = new Date().toISOString();
        const title = body.title || 'Untitled';
        const newItem = {
          id: body.id || slugify(title),
          title,
          type: body.type || 'item',
          status: body.status || 'backlog',
          icon: body.icon || '📄',
          children: [],
          comments: [],
          createdAt: now,
          updatedAt: now
        };
        if (!parent.children) parent.children = [];
        parent.children.push(newItem);
        parent.updatedAt = now;
        writeBoard(board);
        res.statusCode = 201;
        return newItem;
      },

      'PATCH /*/items/:id': (req, res, { body, params }) => {
        const board = readBoard();
        const segments = params['*'].split('/').filter(Boolean);
        const parent = findByPath(board, segments);
        if (!parent) { res.statusCode = 404; return { error: 'Path not found' }; }
        const item = (parent.children || []).find(c => c.id === params.id);
        if (!item) { res.statusCode = 404; return { error: 'Item not found' }; }
        const allowed = ['title', 'status', 'icon', 'type'];
        for (const key of allowed) {
          if (body[key] !== undefined) item[key] = body[key];
        }
        item.updatedAt = new Date().toISOString();
        writeBoard(board);
        return item;
      },

      'DELETE /*/items/:id': (req, res, { body, params }) => {
        const board = readBoard();
        const segments = params['*'].split('/').filter(Boolean);
        const parent = findByPath(board, segments);
        if (!parent) { res.statusCode = 404; return { error: 'Path not found' }; }
        const idx = (parent.children || []).findIndex(c => c.id === params.id);
        if (idx === -1) { res.statusCode = 404; return { error: 'Item not found' }; }
        parent.children.splice(idx, 1);
        parent.updatedAt = new Date().toISOString();
        writeBoard(board);
        return { ok: true };
      },

      'POST /*/items/:id/comments': (req, res, { body, params }) => {
        const board = readBoard();
        const segments = params['*'].split('/').filter(Boolean);
        const parent = findByPath(board, segments);
        if (!parent) { res.statusCode = 404; return { error: 'Path not found' }; }
        const item = (parent.children || []).find(c => c.id === params.id);
        if (!item) { res.statusCode = 404; return { error: 'Item not found' }; }
        const comment = {
          author: body.author || 'Anonymous',
          text: body.text || '',
          timestamp: new Date().toISOString()
        };
        if (!item.comments) item.comments = [];
        item.comments.push(comment);
        item.updatedAt = new Date().toISOString();
        writeBoard(board);
        return comment;
      }
    }
  };
};
