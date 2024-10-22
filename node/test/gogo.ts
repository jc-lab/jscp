import * as jcsp from '../dist/index';

const s = new jcsp.Server();
const c = new jcsp.Client();

(async () => {
  await s.start();
  await c.start();
  console.log(s);
  console.log(c);
})();
