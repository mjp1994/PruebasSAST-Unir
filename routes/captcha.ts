/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CaptchaModel } from '../models/captcha'


function safeCalculate (expression: string): number {
  const tokens = expression.match(/(\d+|[+\-*])/g)

  if (!tokens || tokens.length < 3 || tokens.length % 2 === 0) {
    throw new Error('Invalid expression format')
  }

  let result = Number(tokens[0])
  if (isNaN(result)) {
    throw new Error('Invalid number in expression')
  }

  for (let i = 1; i < tokens.length; i += 2) {
    const operator = tokens[i]
    const nextNum = Number(tokens[i + 1])

    if (isNaN(nextNum)) {
      throw new Error('Invalid number in expression')
    }

    switch (operator) {
      case '+':
        result += nextNum
        break
      case '-':
        result -= nextNum
        break
      case '*':
        result *= nextNum
        break
      default:
        throw new Error('Unsupported operator')
    }
  }

  return result
}

export function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression =
        firstTerm.toString() +
        firstOperator +
        secondTerm.toString() +
        secondOperator +
        thirdTerm.toString()

    let answer: string
    try {
      const numericAnswer = safeCalculate(expression)
      answer = numericAnswer.toString()
    } catch (err) {
      console.error('Captcha calculation failed:', err)
      answer = '0'
    }

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json(captcha)
  }
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const captcha = await CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } })
    if ((captcha != null) && req.body.captcha === captcha.answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}
