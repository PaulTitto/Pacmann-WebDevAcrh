const formLogin = document.getElementById("form-login")
formLogin.addEventListener("submit", function(e){
    e.preventDefault();
  
    let xhr = new XMLHttpRequest();
    let url = "/api/auth/login";
  
    //get data from form
    username = document.getElementById("username").value;
    password = document.getElementById("password").value;
  
    //validasi input
    if (username.trim().length < 0) return alert("Username tidak boleh kosong");
    if (password.trim().length < 0) return alert("password tidak boleh kosong");
  
    let data = JSON.stringify({
      username: username,
      password: password,
    });
  
    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-Type", "application/json;charset=utf-8");
    
    xhr.onreadystatechange = function () {
      if (this.readyState == 4 && this.status == 200) {               
        //   formLogin.reset()
        let data = JSON.parse(this.response)
        //save to token to localStorage
        localStorage.setItem("access_token", data.access_token)
        window.location.href = "/";
      }
  };
    xhr.send(data);

    const alertLoc = document.getElementById("alert-loc")
    const div = document.createElement("div");
    alertLoc.append(div);
})