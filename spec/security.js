describe('security issues', function() {
  describe('GH-1495: Prevent Remote Code Execution via constructor', function() {
    it('should not allow constructors to be accessed', function() {
        shouldCompileTo('{{constructor.name}}', {}, '');
    });

    it('should allow the "constructor" property to be accessed if it is enumerable', function() {
        shouldCompileTo('{{constructor.name}}', {'constructor': {
            'name': 'here we go'
        }}, 'here we go');
    });

    it('should allow prototype properties that are not constructors', function() {
        shouldCompileTo('{{#with this as |obj|}}{{obj.abc}}{{/with}}',
            { abc: 'xyz' }, 'xyz');
    });
  });

  describe('escapes template variables', function() {
    it('in compat mode', function() {
      var template = CompilerContext.compile("{{'a\\b'}}", { compat: true });
      equals(template({ 'a\\b': 'c' }), 'c');
    });

    it('in default mode', function() {
      var template = CompilerContext.compile("{{'a\\b'}}");
      equals(template({ 'a\\b': 'c' }), 'c');
    });
    it('in default mode', function() {
      var template = CompilerContext.compile("{{'a\\b'}}", { strict: true });
      equals(template({ 'a\\b': 'c' }), 'c');
    });
  });

  describe('GH-1631: disallow access to prototype functions', function() {
    function TestClass() {}

    TestClass.prototype.aProperty = 'propertyValue';
    TestClass.prototype.aMethod = function() {
      return 'returnValue';
    };

    describe('control access to prototype non-methods via "allowedProtoProperties" and "allowProtoPropertiesByDefault"', function() {
      describe('in compat-mode', function() {
        checkProtoPropertyAccess({ compat: true });
      });

      describe('in strict-mode', function() {
        checkProtoPropertyAccess({ strict: true });
      });

      function checkProtoPropertyAccess(compileOptions) {
        it('should be prohibited by default and log a warning', function() {
          var template = CompilerContext.compile('{{aProperty}}', compileOptions);
          equals(template(new TestClass()), '');
        });

        it('can be explicitly prohibited by default, which disables the warning', function() {
          var runtimeOptions = {
            allowProtoPropertiesByDefault: false
          };
          var template = CompilerContext.compile('{{aProperty}}', compileOptions);
          equals(template(new TestClass(), runtimeOptions), '');
        });

        it('can be turned on, which disables the warning', function() {
          var runtimeOptions = {
            allowedProtoProperties: {
              aProperty: true
            }
          };
          var template = CompilerContext.compile('{{aProperty}}', compileOptions);
          equals(template(new TestClass(), runtimeOptions), 'propertyValue');
        });

        it('can be turned on by default, which disables the warning', function() {
          var runtimeOptions = {
            allowProtoPropertiesByDefault: true
          };
          var template = CompilerContext.compile('{{aProperty}}', compileOptions);
          equals(template(new TestClass(), runtimeOptions), 'propertyValue');
        });

        it('can be turned off, if turned on by default', function() {
          var runtimeOptions = {
            allowProtoPropertiesByDefault: true,
            allowedProtoProperties: {
              aProperty: false
            }
          };
          var template = CompilerContext.compile('{{aProperty}}', compileOptions);
          equals(template(new TestClass(), runtimeOptions), '');
        });
      }
    });
  });

  describe('GH-1595', function() {
    it('properties, that are required to be enumerable', function() {
      shouldCompileTo('{{constructor}}', {}, '');
      shouldCompileTo('{{__defineGetter__}}', {}, '');
      shouldCompileTo('{{__defineSetter__}}', {}, '');
      shouldCompileTo('{{__lookupGetter__}}', {}, '');
      shouldCompileTo('{{__proto__}}', {}, '');

      shouldCompileTo('{{lookup this "constructor"}}', {}, '');
      shouldCompileTo('{{lookup this "__defineGetter__"}}', {}, '');
      shouldCompileTo('{{lookup this "__defineSetter__"}}', {}, '');
      shouldCompileTo('{{lookup this "__lookupGetter__"}}', {}, '');
      shouldCompileTo('{{lookup this "__proto__"}}', {}, '');
    });
  });
});
