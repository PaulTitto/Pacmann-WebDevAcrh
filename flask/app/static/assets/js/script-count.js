function get_data() {
    //GET TWEET FROM BACKEND
    let xhr = new XMLHttpRequest();
    let url = "http://127.0.0.1:5000/api/counts"; //ganti nama file sesuai nama file json kalian
    xhr.onreadystatechange = function () {
      if (this.readyState == 4 && this.status == 200) {
        let res = JSON.parse(this.response)
        res.data.forEach((count, index) => {
            console.log(count)
            let tbody = document.getElementById("tbody")
            let tr = document.createElement("tr")
            let th_id = document.createElement('th')
            let td_username = document.createElement('td')
            let td_count = document.createElement("td")
            th_id.innerHTML = index + 1
            td_username.innerHTML = count.username
            td_count.innerHTML = count.count_tweet
            tr.append(th_id, td_username, td_count)
            tbody.append(tr)
        });
      }
    }
    xhr.open("GET", url, true);
    xhr.send();
  }
  
  window.onload = function () {
    // cek apakah access_token & 
    if (localStorage.getItem("access_token") == null) {
      const sectionForm = document.getElementById("section-form")
      sectionForm.classList.add("d-none")
    }
    get_data()
  }