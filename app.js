const express = require('express')
const bcrypt = require('bcrypt')
const path = require('path')
const hbs = require('hbs')
const sessions = require('express-session')
const { db } = require('./DB')
const { checkAuth } = require('./src/middlewares/checkAuth')

const server = express()
const PORT = process.env.PORT || 3000

const saltRounds = 10

server.set('view engine', 'hbs')
server.set('views', path.join(process.cwd(), 'src', 'views'))
server.set('cookieName', 'sid')
hbs.registerPartials(path.join(process.cwd(), 'src', 'views', 'partials'))

const secretKey = 'akasljdfalksdjfalskdljf'

server.use(express.urlencoded({ extended: true }))
server.use(express.json())
server.use(express.static('public'))
server.use(sessions({
  name: server.get('cookieName'),
  secret: secretKey,
  resave: false, // Не сохранять сессию, если мы ее не изменим
  saveUninitialized: false, // не сохранять пустую сессию
  // store: new FileStore({ // выбираем в качестве хранилища файловую систему
  //   secret: secretKey,
  // }),
  cookie: { // настройки, необходимые для корректного работы cookie
    // secure: true,
    httpOnly: true, // не разрещаем модифицировать данную cookie через javascript
    maxAge: 86400 * 1e3, // устанавливаем время жизни cookie
  },
}))

server.use((req, res, next) => {
  const currentEmail = req.session?.user?.email

  if (currentEmail) {
    const currentUser = db.users.find((user) => user.email === currentEmail)
    console.log({ currentUser })
    res.locals.name = currentUser.name
  }

  next()
})

server.get('/', (req, res) => {
  res.render('main')
})

server.delete('/fetch', (req, res) => {
  console.log('>>>>>>>>', req.body, req.session)
  res.sendStatus(204)
})

server.get('/secret', checkAuth, (req, res) => {
  res.render('secret')
})

server.get('/auth/signup', (req, res) => {
  res.render('signUp')
})

server.post('/auth/signup', async (req, res) => {
  const { name, email, password } = req.body

  const hashPass = await bcrypt.hash(password, saltRounds)

  db.users.push({
    name,
    email,
    password: hashPass,
  })

  req.session.user = {
    email,
  }

  console.log(db.users)

  res.redirect('/')
})

server.get('/auth/signin', async (req, res) => {
  res.render('signIn')
})

server.post('/auth/signin', async (req, res) => {
  const { email, password } = req.body

  const currentUser = db.users.find((user) => user.email === email)

  if (currentUser) {
    if (await bcrypt.compare(password, currentUser.password)) {
      req.session.user = {
        email,
      }

      return res.redirect('/')
    }
  }

  return res.redirect('/auth/signin')
})

server.get('/auth/signout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.redirect('/')

    res.clearCookie(req.app.get('cookieName'))
    return res.redirect('/')
  })
})

server.get('/', (request, response) => {
  const usersQuery = request.query // = { limit: '1' }
  let peopleForRender = db.people

  if (usersQuery.limit !== undefined && Number.isNaN(+usersQuery.limit) === false) {
    peopleForRender = db.people.slice(0, usersQuery.limit)
  }

  response.render('main', { listOfPeople: peopleForRender })
})

server.post('/addpost', (req, res) => {
  const dataFromForm = req.body

  db.people.push(dataFromForm)

  res.redirect('/')
})

server.listen(PORT, () => {
  console.log(`Server has been started on port: ${PORT}`)
})










