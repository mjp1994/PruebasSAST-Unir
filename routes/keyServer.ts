/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const BASE_DIR = path.resolve('encryptionkeys')
const ALLOWED_FILES = new Set([
  'jwt.pub',
  'jwt.key',
])

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file || typeof file !== 'string' || file.includes('/') || file.includes('\\')) {
      res.status(403)
      return next(new Error('Invalid file name'))
    }

    if (!ALLOWED_FILES.has(file)) {
      res.status(403)
      return next(new Error('Access denied'))
    }

    const targetPath = path.resolve(BASE_DIR, file)

    if (!targetPath.startsWith(BASE_DIR + path.sep)) {
      res.status(403)
      return next(new Error('Access outside of allowed directory is forbidden'))
    }

    res.sendFile(targetPath, (err) => {
      if (err) {
        res.status(404).send('File not found')
      }
    })
  }
}