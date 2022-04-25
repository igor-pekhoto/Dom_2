// if (window.location.pathname === ) {

// }
const $signUpForm = document.forms.signupform
const $fetchBtn = document.querySelector('[data-fetch]')

if ($signUpForm) {
  console.log('work')

  const $emailInput = $signUpForm.elements.email
  const $nameInput = $signUpForm.elements.name

  const LSKey = 'signUpForm'

  const dataFromLS = JSON.parse(window.localStorage.getItem(LSKey))

  $emailInput.value = dataFromLS.email
  $nameInput.value = dataFromLS.name

  $emailInput.addEventListener('input', (e) => {
    console.log(e.target.value)

    const oldData = JSON.parse(window.localStorage.getItem(LSKey))
    console.log({ oldData })

    const objectToSave = {
      ...oldData,
      [e.target.name]: e.target.value,
    }

    window.localStorage.setItem(LSKey, JSON.stringify(objectToSave))
  })

  $nameInput.addEventListener('input', (e) => {
    console.log(e.target.value)

    const oldData = JSON.parse(window.localStorage.getItem(LSKey))
    console.log({ oldData })

    const objectToSave = {
      ...oldData,
      [e.target.name]: e.target.value,
    }

    window.localStorage.setItem(LSKey, JSON.stringify(objectToSave))
  })
}

if ($fetchBtn) {
  $fetchBtn.addEventListener('click', () => {
    fetch('/fetch/', {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ id: Date.now() }),
    })
      .then((response) => { console.log({ response }) })
  })
}
