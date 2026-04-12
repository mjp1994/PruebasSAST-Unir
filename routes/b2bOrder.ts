/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function b2bOrder () {
  return (req: Request, res: Response, next: NextFunction) => {
    const { body } = req
    const cid = body.cid
    if (!utils.isChallengeEnabled(challenges.rceChallenge) &&
        !utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      return res.json({
        cid,
        orderNo: uniqueOrderNumber(),
        paymentDue: dateTwoWeeksFromNow()
      })
    }
    const orderLinesData = body.orderLinesData || ''

    try {
      const parsed = JSON.parse(orderLinesData)

      if (!Array.isArray(parsed)) {
        throw new Error('orderLinesData must be an array')
      }

      for (const item of parsed) {
        if (typeof item !== 'object' || item === null) {
          throw new Error('Invalid order line item')
        }
        if (typeof item.product !== 'string' || typeof item.quantity !== 'number') {
          throw new Error('Invalid order line format')
        }
        if (item.quantity < 1 || item.quantity > 1000) {
          throw new Error('Quantity out of range')
        }
      }

      return res.json({
        cid,
        orderNo: uniqueOrderNumber(),
        paymentDue: dateTwoWeeksFromNow()
      })

    } catch (err: any) {
      const errMsg = utils.getErrorMessage(err)

      if (errMsg.includes('JSON')) {
        return next(new Error('Invalid order data format'))
      }

      if (errMsg.includes('Infinite loop') || errMsg.includes('timeout')) {
        challengeUtils.solveIf(challenges.rceOccupyChallenge, () => true)
        res.status(503)
        return next(new Error('Sorry, we are temporarily not available! Please try again later.'))
      }

      challengeUtils.solveIf(challenges.rceChallenge, () => {
        return false
      })

      return next(err)
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
