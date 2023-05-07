$(document).ready(function() {
  // 取得現在時間
  var now = new Date();
  // 計算過去 6 小時的時間範圍
  var past6Hours = new Date(now - 6 * 60 * 60 * 1000);

  // 格式化日期和時間
  var formatDate = function(date) {
    var year = date.getFullYear();
    var month = ("0" + (date.getMonth() + 1)).slice(-2);
    var day = ("0" + date.getDate()).slice(-2);
    var hour = ("0" + date.getHours()).slice(-2);
    var minute = ("0" + date.getMinutes()).slice(-2);
    var second = ("0" + date.getSeconds()).slice(-2);
    return year + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + second;
  };

  // 格式化目前時間和過去6小時時間
  var startTime = formatDate(past6Hours);
  var endTime = formatDate(now);

  // 發送AJAX請求
  $.ajax({
    url: '/authentication/my-api-url',
    data: {
      start_time: startTime,
      end_time: endTime
    },
    success: function(data) {
      // 解析 API 回傳的資料
      var hourly_counts = data.hourly_counts;
      var past_counts = data.past_counts;

      // 設置折線圖的標籤和數據
      var labels = ['0時', '1時', '2時', '3時', '4時', '5時', '6時', '7時', '8時', '9時', '10時', '11時', '12時', '13時', '14時', '15時', '16時', '17時', '18時', '19時', '20時', '21時', '22時', '23時'];
      var datasets = [
        {
          label: '每小時的登入次數',
          data: hourly_counts,
          borderColor: 'rgba(54, 162, 235, 1)',
          fill: false
        }
      ];

      // 繪製折線圖
      var ctx = document.getElementById('login-count-chart').getContext('2d');
      var chart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: labels,
          datasets: datasets
        },
        options: {
          scales: {
            yAxes: [{
              ticks: {
                stepSize: 1,
                callback: function(value, index, values) {
                  return parseInt(value)
                },
                max: Math.max(...hourly_counts) + 10 // 將 max 設置為數據中的最大值加上 1
              }
            }]
          }
        }
      });

      // 在網頁上顯示目前時間
      var currentTime = formatDate(now);
      $('#current-time').text(currentTime);
    }
  });
});
