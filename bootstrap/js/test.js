console.log("begin output");


function showData(data){
  console.log("get the data back");
    for (var key in data) {
      var para = document.createElement("p");
      var node = document.createTextNode(key);
      para.appendChild(node);
      var result = document.getElementById("result");
      result.appendChild(para);
      if (data.hasOwnProperty(key)) {
        console.log(key + " -> " + data[key]);
        var para = document.createElement("p");
        var node = document.createTextNode(data[key]);
        para.appendChild(node);
        var result = document.getElementById("result");
        result.appendChild(para);
      }
  }
}


function handleClick(e){
  $.ajax('/test',{
    type: 'GET',
    data: {
      fmt: 'json'
    },
    success: showData
  });
}


$(document).ready( function(){
  $('#sub').on('click', handleClick);
});
