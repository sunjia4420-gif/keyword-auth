const { createClient } = require('@supabase/supabase-js');

// 直接使用正确的 Supabase 凭据（忽略环境变量，避免配置错误）
const supabaseUrl = 'https://wgjhijtfhqtkdgddtcwh.supabase.co';
const supabaseKey = 'sb_publishable_4JkQtzY24ldcGfE7BcZs0Q_hdN1Ms-e';
const supabase = createClient(supabaseUrl, supabaseKey);

// ==================== 口令操作 ====================

// 根据口令值查找
async function findPasswordByValue(password) {
  const { data, error } = await supabase
    .from('passwords')
    .select('*')
    .eq('password', password)
    .single();
  
  if (error || !data) return null;
  return data;
}

// 增加使用次数
async function incrementPasswordUsage(id) {
  const { error } = await supabase.rpc('increment_password_usage', { pwd_id: id });
  // 如果 RPC 不存在，用原始方式
  if (error) {
    const { data } = await supabase
      .from('passwords')
      .select('used_count')
      .eq('id', id)
      .single();
    if (data) {
      await supabase
        .from('passwords')
        .update({ used_count: (data.used_count || 0) + 1 })
        .eq('id', id);
    }
  }
}

// 获取所有口令
async function getAllPasswords() {
  const { data, error } = await supabase
    .from('passwords')
    .select('*')
    .order('created_at', { ascending: false });
  return data || [];
}

// 创建口令
async function createPassword({ name, password, expires_at, max_uses }) {
  const { data, error } = await supabase
    .from('passwords')
    .insert([{ name, password, expires_at, max_uses, is_active: 1 }])
    .select();
  
  if (error) return { success: false, message: error.message };
  return { success: true, password: data[0] };
}

// 更新口令
async function updatePassword(id, updates) {
  const { error } = await supabase
    .from('passwords')
    .update(updates)
    .eq('id', id);
  
  if (error) return { success: false, message: error.message };
  return { success: true };
}

// 删除口令
async function deletePassword(id) {
  const { error } = await supabase
    .from('passwords')
    .delete()
    .eq('id', id);
  
  if (error) return { success: false, message: error.message };
  return { success: true };
}

// ==================== 访问日志 ====================

async function addLog({ password_id, password_name, ip_address, user_agent }) {
  const { error } = await supabase
    .from('access_logs')
    .insert([{ password_id, password_name, ip_address, user_agent }]);
  if (error) console.error('记录日志失败:', error);
}

async function getAllLogs() {
  const { data, error } = await supabase
    .from('access_logs')
    .select('*')
    .order('accessed_at', { ascending: false })
    .limit(500);
  return data || [];
}

// ==================== 系统设置 ====================

async function getSetting(key) {
  const { data, error } = await supabase
    .from('settings')
    .select('value')
    .eq('key', key)
    .single();
  
  if (error || !data) return null;
  return data.value;
}

async function saveSetting(key, value) {
  const { error } = await supabase
    .from('settings')
    .upsert({ key, value }, { onConflict: 'key' });
  
  if (error) console.error('保存设置失败:', error);
}

module.exports = {
  findPasswordByValue,
  incrementPasswordUsage,
  getAllPasswords,
  createPassword,
  updatePassword,
  deletePassword,
  addLog,
  getAllLogs,
  getSetting,
  saveSetting
};
