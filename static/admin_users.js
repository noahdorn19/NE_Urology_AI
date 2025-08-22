// --- Admin Users page logic (admin_users.js) ---
// Requires the admin_users.html table to have:
// <tbody id="tbody"> with rows like <tr data-user="username">…
// checkboxes with .adminbox
// <select class="deptselect"> for department (optional)
// Buttons that call doReset(user), deleteUser(user) already present in template.

const toastEl = document.getElementById('toast');
const saveBtn = document.getElementById('save-pending'); // <button id="save-pending">Save</button>
const tbody = document.getElementById('tbody');

const pending = {}; // pending[username] = { role, department }

function showToast(message){
  if(!toastEl) return alert(message);
  toastEl.textContent = message;
  toastEl.classList.add('show');
  setTimeout(()=> toastEl.classList.remove('show'), 1600);
}

function updateSaveBtn(){
  if (!saveBtn) return;
  const has = Object.keys(pending).length > 0;
  saveBtn.disabled = !has;
}

async function setRole(user, isAdmin){
  const fd = new FormData();
  fd.append('target', user);
  fd.append('role', isAdmin ? 'admin' : 'user');
  const res = await fetch('/admin/set_role', { method:'POST', body: fd });
  if(!res.ok) throw new Error(await res.text());
  showToast(`Role → ${isAdmin ? 'admin' : 'user'}`);
}

async function setDepartment(user, dept){
  const fd = new FormData();
  fd.append('target', user);
  fd.append('department', dept || '');
  const res = await fetch('/admin/set_department', { method:'POST', body: fd });
  if(!res.ok) throw new Error(await res.text());
  showToast(`Department → ${dept || 'user/None'}`);
}

async function doReset(user){
  const fd = new FormData(); fd.append('target', user);
  const res = await fetch('/admin/reset_password', { method:'POST', body: fd });
  const data = await res.json();
  if(data.ok){
    alert(`Temporary password for ${user}: ${data.temp_password}\nUser must set a new password on next login.`);
    showToast('Temporary password generated');
  } else {
    showToast('Reset failed'); alert('Reset failed: '+JSON.stringify(data));
  }
}

async function deleteUser(user){
  if(!confirm(`Delete user "${user}"? This cannot be undone.`)) return;
  const fd = new FormData(); fd.append('target', user);
  const res = await fetch('/admin/delete_user', { method:'POST', body: fd });
  if(!res.ok){
    alert('Delete failed: ' + await res.text());
    return;
  }
  const row = tbody.querySelector(`[data-user="${user}"]`);
  row && row.remove();
  delete pending[user];
  updateSaveBtn();
  showToast('User deleted');
}

function updatePills(row, roleIsAdmin){
  const cell = row.querySelector('td:first-child');
  let adminP = cell.querySelector('.pill.admin');
  if (roleIsAdmin) {
    if (!adminP) { adminP = document.createElement('span'); adminP.className='pill admin'; adminP.textContent='admin'; cell.appendChild(adminP); }
  } else if (adminP) { adminP.remove(); }
}

function attachHandlers(row){
  const user = row.dataset.user;
  const adminBox = row.querySelector('.adminbox');
  const deptSel = row.querySelector('.deptselect');

  if (adminBox) {
    adminBox.addEventListener('change', () => {
      pending[user] = pending[user] || {};
      pending[user].role = adminBox.checked ? 'admin' : 'user';
      updatePills(row, adminBox.checked);
      updateSaveBtn();
    });
  }

  if (deptSel) {
    deptSel.addEventListener('change', () => {
      pending[user] = pending[user] || {};
      pending[user].department = deptSel.value || '';
      updateSaveBtn();
    });
  }
}

tbody?.querySelectorAll('tr[data-user]').forEach(attachHandlers);

saveBtn?.addEventListener('click', async () => {
  // Persist pending changes sequentially (simple and robust)
  const entries = Object.entries(pending);
  try{
    for (const [user, changes] of entries) {
      if ('role' in changes) await setRole(user, changes.role === 'admin');
      if ('department' in changes) await setDepartment(user, changes.department);
      delete pending[user];
    }
    updateSaveBtn();
    showToast('Saved changes');
  } catch (err){
    alert('Save failed: ' + err.message);
  }
});

// Expose functions for template buttons
window.doReset = doReset;
window.deleteUser = deleteUser;