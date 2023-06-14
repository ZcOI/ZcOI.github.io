// 获取相关 DOM 元素
const openBtn = document.querySelector('.open-btn')
const closeBtn = document.querySelector('.close-btn')
const sidebar = document.querySelector('.sidebar')
const overlay = document.querySelector('.overlay')

// 为打开和关闭按钮添加点击事件处理程序
openBtn.addEventListener('click', () => {
  sidebar.classList.add('open')
  overlay.classList.add('open')
})
closeBtn.addEventListener('click', () => {
  sidebar.classList.remove('open')
  overlay.classList.remove('open')
})
overlay.addEventListener('click', () => {
  sidebar.classList.remove('open')
  overlay.classList.remove('open')
})
