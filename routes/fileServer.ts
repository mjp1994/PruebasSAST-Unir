/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

const BASE_DIR = path.resolve('ftp')
const ALLOWED_EXTENSIONS = ['.md', '.pdf']

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    let file = params.file

    if (!file || typeof file !== 'string') {
      return res.status(403).send('Invalid filename')
    }

    if (
        file.includes('..') ||
        file.includes('/') ||
        file.startsWith('/') ||
        file.startsWith('\\') ||
        file.includes('%2e%2e') ||
        file.includes('....') ||
        file.includes('%252e%252e')
    ) {
      return res.status(403).send('Path traversal attempt detected')
    }

    if (
        !endsWithAllowlistedFileType(file) &&
        file.toLowerCase() !== 'incident-support.kdbx'
    ) {
      return res.status(403).send('Only .md and .pdf files are allowed!')
    }

    file = security.cutOffPoisonNullByte(file)

    const targetPath = path.resolve(BASE_DIR, file)

    if (!targetPath.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).send('Access outside of allowed directory is forbidden')
    }

    challengeUtils.solveIf(challenges.directoryListingChallenge, () => {
      return file.toLowerCase() === 'acquisitions.md'
    })

    verifySuccessfulPoisonNullByteExploit(file)

    res.sendFile(targetPath, (err) => {
      if (err) {
        res.status(404).send('File not found')
      }
    })
  }
}

function verifySuccessfulPoisonNullByteExploit (file: string) {
  challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => {
    return file.toLowerCase() === 'eastere.gg'
  })
  challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => {
    return file.toLowerCase() === 'package.json.bak'
  })
  challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => {
    return file.toLowerCase() === 'coupons_2013.md.bak'
  })
  challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => {
    return file.toLowerCase() === 'suspicious_errors.yml'
  })

  challengeUtils.solveIf(challenges.nullByteChallenge, () => {
    return (
        challenges.easterEggLevelOneChallenge.solved ||
        challenges.forgottenDevBackupChallenge.solved ||
        challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved ||
        file.toLowerCase() === 'encrypt.pyc'
    )
  })
}

function endsWithAllowlistedFileType (param: string) {
  return ALLOWED_EXTENSIONS.some(ext => utils.endsWith(param.toLowerCase(), ext))
}
