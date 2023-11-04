const formRegister = document.getElementById("form-register");
formRegister.addEventListener("submit", function (e) {
  e.preventDefault();
  
  let xhr = new XMLHttpRequest();
  let url = "/api/auth/register";

  //get data from form
  username = document.getElementById("username").value;
  email = document.getElementById("email").value;
  password = document.getElementById("password").value;
  confirm_password = document.getElementById("confirm-password").value;
  role = document.getElementById("role").value
  //validasi input
  if (username == "") return alert("Username tidak boleh kosong");
  if (email == "") return alert("email tidak boleh kosong");
  if (password == "") return alert("password tidak boleh kosong");
  if (password != confirm_password)
    return alert("password yang dimasukan tidak sama");

  let data = JSON.stringify({
    username: username,
    email: email,
    password: password,
    role: role
  });
  

  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.send(data);
  xhr.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
        div.innerHTML = "Data berhasil ditambahkan !";
        div.setAttribute("class", "alert alert-success");
        div.setAttribute("role", "alert");
        formRegister.reset()
      }else{
        div.setAttribute("class", "alert alert-danger");
        div.innerHTML = "Ada masalah!";
        div.setAttribute("role", "alert");
    }
};

  //give feedback
  const alertLoc = document.getElementById("alert-loc")
  const div = document.createElement("div");
  alertLoc.append(div);
});


