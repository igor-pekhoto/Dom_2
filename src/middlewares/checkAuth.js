const checkAuth = (req, res, next) => {
  const currentUser = req.session?.user

  if (currentUser) {
    return next()
  }

  return res.redirect('/auth/signin')
}

module.exports = {
  checkAuth,
}
