
const usernameField = document.querySelector("#usernameField");
const feedBackArea = document.querySelector(".invalid_feedback");
const emailField = document.querySelector("#emailField");
const emailfeedBackArea = document.querySelector(".emailfeedBackArea");
const passwordField = document.querySelector("#passwordField");
const usernameSuccessOutput = document.querySelector(".usernameSuccessOutput");
const passwordFeedbackArea = document.querySelector(".passwordFeedbackArea");
const togglePasswordButton = document.querySelector('.passwordToggleBtn');
const togglePasswordIcon = document.querySelector('#togglePasswordIcon');
const submitBtn = document.querySelector('.submit-btn');


togglePasswordButton.addEventListener('click', function (e) {
    const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordField.setAttribute('type', type);
    
    // 切換圖示
    if (type === 'password') {
        togglePasswordIcon.classList.add('fa-eye-slash');
        togglePasswordIcon.classList.remove('fa-eye');
    } else {
        togglePasswordIcon.classList.add('fa-eye');
        togglePasswordIcon.classList.remove('fa-eye-slash');
    }
});

passwordField.addEventListener('input', (event) => {
    const password = event.target.value;
    // 檢查密碼是否符合要求
    if (password.length < 8) {
        passwordFeedbackArea.innerHTML = '密碼必須至少包含 8 個字符';
    } else if (!/[A-Z]/.test(password)) {
        passwordFeedbackArea.innerHTML = '密碼必須至少包含一個大寫字母';
    } else if (!/[a-z]/.test(password)) {
        passwordFeedbackArea.innerHTML = '密碼必須至少包含一個小寫字母';
    } else {
        // 密码符合要求，清除错误消息
        passwordFeedbackArea.innerHTML = '';
    }
});



emailField.addEventListener("keyup", (e)=>{

    console.log("666",666);
    const emailVal=e.target.value;


    emailField.classList.remove("is-invalid");
    emailfeedBackArea.style.display = "none";

    if (emailVal.length > 0) {
        fetch("/authentication/validate-email", {
            body: JSON.stringify({ email: emailVal }),
            method: "POST",
        })
        .then((res) => res.json())
        .then((data) => {
            console.log("data",data);
            if(data.email_error){
                emailField.classList.add("is-invalid");
                emailfeedBackArea.style.display = "block";
                emailfeedBackArea.innerHTML=`<p>${data.email_error}</p>`;
                submitBtn.disabled= true;

            }else{
                submitBtn.removeAttribute('disabled')
            }
        });
    }

    
})




usernameField.addEventListener("keyup", (e) => {
    const usernameVal=e.target.value;

    usernameSuccessOutput.style.display = "block";

    usernameSuccessOutput.textContent=`Checking  ${usernameVal}`


    usernameField.classList.remove("is-invalid");
    feedBackArea.style.display = "none";

    if (usernameVal.length > 0) {
        fetch("/authentication/validate-username", {
            body: JSON.stringify({ username: usernameVal }),
            method: "POST",
        })
        .then((res) => res.json())
        .then((data) => {
            usernameSuccessOutput.style.display = "none";
            if(data.username_error){
                usernameField.classList.add("is-invalid");
                feedBackArea.style.display = "block";
                feedBackArea.innerHTML=`<p>${data.username_error}</p>`;
                submitBtn.disabled= true;
            }else{
                submitBtn.removeAttribute('disabled')
            }
        });
    }
});