// 獲取要顯示當前時間的元素
var currentTimeElem = document.getElementById("current-time");

// 更新當前時間
function updateCurrentTime() {
  var now = new Date();
  var year = now.getFullYear();
  var month = ("0" + (now.getMonth() + 1)).slice(-2);
  var day = ("0" + now.getDate()).slice(-2);
  var hour = ("0" + now.getHours()).slice(-2);
  var minute = ("0" + now.getMinutes()).slice(-2);
  var second = ("0" + now.getSeconds()).slice(-2);
  var currentTimeStr = year + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + second;
  currentTimeElem.textContent = currentTimeStr;
}

// 每秒更新當前時間
setInterval(updateCurrentTime, 1000);
