//@ts-check
const express = require('express')
const sqlite3 = require('sqlite3')
const session = require('express-session')
const { authenticator } = require('otplib')
const QRCode = require('qrcode')
const bodyParser = require('body-parser')
const app = express()
const port = 3000

app.set('view engine', 'ejs')

app.use(session({
  secret: 'supersecretTest',
}))


app.use(bodyParser.urlencoded({ extended: false }))

app.get('/', (req, res) => {
  res.render('newUser.ejs')
})

app.post('/sign-up', (req, res) => {
  const email = req.body.email,
    secret = authenticator.generateSecret()

  const db = new sqlite3.Database('db.sqlite')
  db.serialize(() => {
    db.run('INSERT INTO `users`(`email`, `secret`) VALUES (?, ?)',
      [email, secret],
      (err) => {
        if (err) {
          throw err
        }

        //generate qr and put it in session
        QRCode.toDataURL(authenticator.keyuri(email, '2FA Node App', secret), (err, url) => {
          if (err) {
            throw err
          }

          req.session.qr = url
          req.session.email = email
          res.redirect('/sign-up-2fa')
        })
      })
  })
})

app.get('/sign-up-2fa', (req, res) => {
  if (!req.session.qr) {
    return res.redirect('/')
  }

  return res.render('signup-2fa.ejs', { qr: req.session.qr })
})

app.post('/sign-up-2fa', (req, res) => {
  if (!req.session.email) {
    return res.redirect('/')
  }

  const email = req.session.email,
    code = req.body.code

  return verifyLogin(email, code, req, res, '/sign-up-2fa')
})

function LoginMiddleware(req, res, next) {
  if (!req.session?.email)
    return res.redirect("/")

    req.user = req.session.email;
  next();

}

app.get('/login', (req, res) => {
  return res.render('login.ejs')
})

app.post('/login', (req, res) => {
  //NOTE verify login
  const email = req.body.email,
    code = req.body.code

  return verifyLogin(email, code, req, res, '/login')
})

app.get('/is_user', LoginMiddleware, (req, res) => {
  
  QRCode.toDataURL(authenticator.keyuri(req.session.email, '2FA Node App', req.session.secret), (err, url) => {
    if (err) {
      throw err
    }
    return res.render('UserArea.ejs', {
      email: req.user,
      qr :url,
      data:req.session.secret,
    })
  })

  
})

app.get('/logout', LoginMiddleware, (req, res) => {
  if ( req.session?.destroy)
    req.session.destroy();
  return res.redirect('/')
})

function verifyLogin(email, code, req, res, failUrl) {


  const db = new sqlite3.Database('db.sqlite')
  db.serialize(() => {
    db.get('SELECT secret FROM users WHERE email = ?', [email], (err, row) => {
      if (err) {
        throw err
      }

      if (!row) {
        return res.redirect('/')
      }

      if (!authenticator.check(code, row.secret)) {
        //NOTE redirect back
        return res.redirect(failUrl)
      }
      req.session.qr = null
      req.session.email = email;
      req.session.secret=row.secret;

      //NOTE redirect to "private" page
      return res.redirect('/is_user')
    })
  })
}

//NOTE create database with tables if it doesn't exist

const db = new sqlite3.Database('db.sqlite')
db.serialize(() => {
  db.run('CREATE TABLE IF NOT EXISTS `users` (`user_id` INTEGER PRIMARY KEY AUTOINCREMENT, `email` VARCHAR(255) NOT NULL, `secret` varchar(255) NOT NULL)')
})
db.close()

app.listen(port, () => {
  console.log(`2fa at http://localhost:${port}`)
})