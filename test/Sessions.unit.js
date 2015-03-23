var assert = require('assert');

var Sessions = require('../');

describe('Sessions', function() {
  
  it('should expose a constructor', function() {
    assert(typeof Sessions, 'function');
  });
  
  it('should correctly instantiate without parameters', function() {
    var sessions = new Sessions();
  });
  
});
