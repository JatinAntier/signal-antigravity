/**
 * rootSaga.js
 * Combines all sagas into the root saga
 */

import {all, fork} from 'redux-saga/effects';
import authSaga from './authSaga';
import chatSaga from './chatSaga';
import callsSaga from './callsSaga';

export default function* rootSaga() {
  yield all([
    fork(authSaga),
    fork(chatSaga),
    fork(callsSaga),
  ]);
}
