// 削除・取り下げの確認。キャンセルなら送信しません。
document.querySelectorAll('form[data-confirm]').forEach((form) => {
  form.addEventListener('submit', (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});

// 曜日を入力中にも表示します。正式な曜日はPythonでも計算します。
const dateInput = document.getElementById('match_date');
const dayPreview = document.getElementById('day-preview');
if (dateInput && dayPreview) {
  const showDay = () => {
    if (!dateInput.value) { dayPreview.textContent = ''; return; }
    const [year, month, day] = dateInput.value.split('-').map(Number);
    const selected = new Date(0);
    selected.setFullYear(year, month - 1, day);
    dayPreview.textContent = '曜日：' + '日月火水木金土'[selected.getDay()];
  };
  dateInput.addEventListener('change', showDay);
  showDay();
}
