// server.js
// server.js
import express from 'express';
import sqlite3pkg from 'sqlite3';
import cors from 'cors';
import path from 'path';
import multer from 'multer';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const sqlite3 = sqlite3pkg.verbose();
const app = express();
const SECRET_KEY = 'seu_chave_secreta_aqui_mude_em_producao';


// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configurar multer para upload
const upload = multer({ 
  dest: 'uploads/',
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Apenas arquivos PDF são permitidos'));
    }
  }
});

// Inicializar banco de dados SQLite
const db = new sqlite3.Database('./database.db', (err) => {
  if (err) console.error('Erro ao conectar ao banco:', err);
  else console.log('Conectado ao SQLite');
});

// Criar tabelas se não existirem
const criarTabelas = () => {
  db.serialize(() => {
    // Tabela de usuários
    db.run(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        senha TEXT NOT NULL,
        tipo TEXT NOT NULL DEFAULT 'cliente',
        departamento TEXT,
        criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de pedidos
    db.run(`
      CREATE TABLE IF NOT EXISTS pedidos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cliente_id INTEGER NOT NULL,
        arquivo TEXT NOT NULL,
        quantidade INTEGER NOT NULL,
        descricao TEXT NOT NULL,
        status TEXT DEFAULT 'em_producao',
        data_pedido DATETIME DEFAULT CURRENT_TIMESTAMP,
        data_entrega DATE NOT NULL,
        criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (cliente_id) REFERENCES usuarios(id)
      )
    `);

    // Inserir usuário admin se não existir
    db.run(`
      INSERT OR IGNORE INTO usuarios (id, nome, email, senha, tipo) 
      VALUES (1, 'Administrador', 'admin@grafica.com', ?, 'admin')
    `, [bcrypt.hashSync('123456', 8)]);

    console.log('Tabelas criadas com sucesso!');
  });
};

criarTabelas();

// Middleware de autenticação
const verificarToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Token não fornecido' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ erro: 'Token inválido' });
    req.usuarioId = decoded.id;
    req.usuarioTipo = decoded.tipo;
    next();
  });
};

// ============ AUTENTICAÇÃO ============

app.post('/api/login', (req, res) => {
  const { email, senha } = req.body;

  db.get('SELECT * FROM usuarios WHERE email = ?', [email], (err, usuario) => {
    if (err) return res.status(500).json({ erro: 'Erro no servidor' });
    if (!usuario) return res.status(401).json({ erro: 'Email ou senha inválidos' });

    if (!bcrypt.compareSync(senha, usuario.senha)) {
      return res.status(401).json({ erro: 'Email ou senha inválidos' });
    }

    const token = jwt.sign(
      { id: usuario.id, tipo: usuario.tipo },
      SECRET_KEY,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        tipo: usuario.tipo,
        departamento: usuario.departamento
      }
    });
  });
});

app.post('/api/registrar', (req, res) => {
  const { nome, email, senha, departamento } = req.body;

  const senhaHash = bcrypt.hashSync(senha, 8);

  db.run(
    'INSERT INTO usuarios (nome, email, senha, departamento, tipo) VALUES (?, ?, ?, ?, ?)',
    [nome, email, senhaHash, departamento, 'cliente'],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ erro: 'Email já cadastrado' });
        }
        return res.status(500).json({ erro: 'Erro ao registrar' });
      }

      const token = jwt.sign(
        { id: this.lastID, tipo: 'cliente' },
        SECRET_KEY,
        { expiresIn: '24h' }
      );

      res.json({
        token,
        usuario: {
          id: this.lastID,
          nome,
          email,
          tipo: 'cliente',
          departamento
        }
      });
    }
  );
});

// ============ PEDIDOS ============

app.get('/api/pedidos', verificarToken, (req, res) => {
  if (req.usuarioTipo === 'admin') {
    db.all(`
      SELECT p.*, u.nome as cliente_nome 
      FROM pedidos p 
      JOIN usuarios u ON p.cliente_id = u.id
      ORDER BY p.criado_em DESC
    `, (err, pedidos) => {
      if (err) return res.status(500).json({ erro: 'Erro ao buscar pedidos' });
      res.json(pedidos);
    });
  } else {
    db.all(
      'SELECT * FROM pedidos WHERE cliente_id = ? ORDER BY criado_em DESC',
      [req.usuarioId],
      (err, pedidos) => {
        if (err) return res.status(500).json({ erro: 'Erro ao buscar pedidos' });
        res.json(pedidos);
      }
    );
  }
});

app.post('/api/pedidos', verificarToken, upload.single('arquivo'), (req, res) => {
  const { descricao, quantidade, data_entrega } = req.body;

  if (!req.file || !descricao || !quantidade || !data_entrega) {
    return res.status(400).json({ erro: 'Campos obrigatórios não preenchidos' });
  }

  db.run(
    'INSERT INTO pedidos (cliente_id, arquivo, descricao, quantidade, data_entrega) VALUES (?, ?, ?, ?, ?)',
    [req.usuarioId, req.file.originalname, descricao, quantidade, data_entrega],
    function(err) {
      if (err) return res.status(500).json({ erro: 'Erro ao criar pedido' });
      res.json({ id: this.lastID, mensagem: 'Pedido criado com sucesso!' });
    }
  );
});

app.put('/api/pedidos/:id/status', verificarToken, (req, res) => {
  if (req.usuarioTipo !== 'admin') {
    return res.status(403).json({ erro: 'Acesso negado' });
  }

  const { status } = req.body;
  db.run(
    'UPDATE pedidos SET status = ? WHERE id = ?',
    [status, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ erro: 'Erro ao atualizar' });
      res.json({ mensagem: 'Status atualizado com sucesso!' });
    }
  );
});

app.delete('/api/pedidos/:id', verificarToken, (req, res) => {
  if (req.usuarioTipo !== 'admin') {
    return res.status(403).json({ erro: 'Acesso negado' });
  }

  db.run('DELETE FROM pedidos WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ erro: 'Erro ao deletar' });
    res.json({ mensagem: 'Pedido deletado com sucesso!' });
  });
});

// ============ USUÁRIOS ============

app.get('/api/usuarios', verificarToken, (req, res) => {
  if (req.usuarioTipo !== 'admin') {
    return res.status(403).json({ erro: 'Acesso negado' });
  }

  db.all('SELECT id, nome, email, tipo, departamento FROM usuarios WHERE tipo = ?', 
    ['cliente'], 
    (err, usuarios) => {
      if (err) return res.status(500).json({ erro: 'Erro ao buscar usuários' });
      res.json(usuarios);
    }
  );
});

// ============ ESTATÍSTICAS ============

app.get('/api/estatisticas', verificarToken, (req, res) => {
  if (req.usuarioTipo !== 'admin') {
    return res.status(403).json({ erro: 'Acesso negado' });
  }

  db.get(`
    SELECT 
      COUNT(*) as total_pedidos,
      SUM(CASE WHEN status = 'em_producao' THEN 1 ELSE 0 END) as em_producao,
      SUM(CASE WHEN status = 'concluido' THEN 1 ELSE 0 END) as concluidos,
      SUM(CASE WHEN status = 'atrasado' THEN 1 ELSE 0 END) as atrasados
    FROM pedidos
  `, (err, stats) => {
    if (err) return res.status(500).json({ erro: 'Erro ao buscar estatísticas' });
    res.json(stats);
  });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});