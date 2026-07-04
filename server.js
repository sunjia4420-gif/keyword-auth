const express = require('express');
const session = require('express-session');
const path = require('path');
const { 
  findPasswordByValue, 
  incrementPasswordUsage, 
  addLog, 
  getSetting, 
  saveSetting,
  getAllPasswords,
  createPassword,
  updatePassword,
  deletePassword,
  getAllLogs
} = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// 中间件
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'keyword-auth-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

// ==================== 认证中间件 ====================
function requireAuth(req, res, next) {
  if (req.session && req.session.passwordId) {
    next();
  } else {
    res.redirect('/login');
  }
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    next();
  } else {
    res.status(401).json({ success: false, message: '需要管理员权限' });
  }
}

// ==================== 路由 ====================

// 根路径重定向到登录页
app.get('/', (req, res) => {
  if (req.session && req.session.passwordId) {
    res.redirect('/tool');
  } else {
    res.redirect('/login');
  }
});

// 登录页
app.get('/login', (req, res) => {
  if (req.session && req.session.passwordId) {
    res.redirect('/tool');
  } else {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

// 工具页（受保护）
app.get('/tool', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'tool.html'));
});

// 管理后台（可选，受保护）
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ==================== API ====================

// 检查登录状态
app.get('/api/check-auth', (req, res) => {
  res.json({
    success: !!(req.session && req.session.passwordId),
    isAdmin: !!(req.session && req.session.isAdmin)
  });
});

// 验证口令
app.post('/api/verify', async (req, res) => {
  const { password } = req.body;
  
  if (!password || !password.trim()) {
    return res.json({ success: false, message: '请输入口令' });
  }

  try {
    const pwd = await findPasswordByValue(password.trim());
    
    // 调试：返回详细信息
    if (!pwd) {
      // 尝试直接查询看是否是连接问题
      const { createClient } = require('@supabase/supabase-js');
      const testClient = createClient(
        process.env.SUPABASE_URL || 'https://wgjhijtfhqtkdgddtcwh.supabase.co',
        process.env.SUPABASE_ANON_KEY || 'sb_publishable_4JkQtzY24ldcGfE7BcZs0Q_hdN1Ms-e'
      );
      const { data: rawData, error: rawError } = await testClient
        .from('passwords')
        .select('id,password,is_active')
        .eq('password', password.trim());
      return res.json({ 
        success: false, 
        message: '口令错误',
        debug: {
          envUrl: process.env.SUPABASE_URL ? '(set)' : '(default)',
          envKey: process.env.SUPABASE_ANON_KEY ? '(set)' : '(default)',
          rawError: rawError ? rawError.message : null,
          rawData: rawData,
          searchingFor: password.trim()
        }
      });
    }
    
    if (pwd.is_active !== 1) {
      return res.json({ success: false, message: '口令已禁用' });
    }
    
    // 检查过期
    if (pwd.expires_at) {
      const expireTime = new Date(pwd.expires_at);
      if (expireTime < new Date()) {
        return res.json({ success: false, message: '口令已过期' });
      }
    }
    
    // 检查使用次数
    if (pwd.max_uses && pwd.used_count >= pwd.max_uses) {
      return res.json({ success: false, message: '口令使用次数已用完' });
    }
    
    // 验证成功
    req.session.passwordId = pwd.id;
    req.session.passwordName = pwd.name;
    
    // 记录日志
    await incrementPasswordUsage(pwd.id);
    await addLog({
      password_id: pwd.id,
      password_name: pwd.name,
      ip_address: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      user_agent: req.headers['user-agent']
    });
    
    res.json({ success: true });
  } catch (err) {
    console.error('验证错误:', err);
    res.json({ success: false, message: '服务器错误' });
  }
});

// 登出
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ==================== 管理员 API ====================

// 管理员登录
app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  const adminPassword = await getSetting('admin_password');
  
  if (password === adminPassword) {
    req.session.isAdmin = true;
    res.json({ success: true });
  } else {
    res.json({ success: false, message: '管理员密码错误' });
  }
});

// 获取所有口令
app.get('/api/admin/passwords', requireAdmin, async (req, res) => {
  const passwords = await getAllPasswords();
  res.json({ success: true, passwords });
});

// 创建口令
app.post('/api/admin/passwords', requireAdmin, async (req, res) => {
  const result = await createPassword(req.body);
  res.json(result);
});

// 更新口令
app.put('/api/admin/passwords/:id', requireAdmin, async (req, res) => {
  const result = await updatePassword(req.params.id, req.body);
  res.json(result);
});

// 删除口令
app.delete('/api/admin/passwords/:id', requireAdmin, async (req, res) => {
  const result = await deletePassword(req.params.id);
  res.json(result);
});

// 获取访问日志
app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  const logs = await getAllLogs();
  res.json({ success: true, logs });
});

// 获取系统设置
app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  const adminPassword = await getSetting('admin_password');
  res.json({ success: true, settings: { admin_password: adminPassword } });
});

// 更新系统设置
app.put('/api/admin/settings', requireAdmin, async (req, res) => {
  const { admin_password } = req.body;
  await saveSetting('admin_password', admin_password);
  res.json({ success: true });
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`✅ 服务器运行中: http://localhost:${PORT}`);
  console.log(`   登录页: http://localhost:${PORT}/login`);
  console.log(`   默认口令: test001`);
});
