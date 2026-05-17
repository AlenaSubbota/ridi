// target=_blank 새 창으로 띄우기 위해
var d = document.getElementsByTagName('a');
for (var i = 0; i < d.length; i++) {
    if (d[i].getAttribute('target') == '_blank') {
        d[i].removeAttribute('target');
        d[i].href += '#_blank'
    }
}
