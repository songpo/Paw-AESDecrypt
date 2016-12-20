import {
    UnitTest, registerTest, against, targets, desc
} from '../__utils__/TestUtils'

import {
    ClassMock
} from '../__mocks__/Mocks'

import DynamicValue from '../DynamicValue'

@registerTest
@against(DynamicValue)
export class TestDynamicValue extends UnitTest {

    @targets('evaluate')
    @desc('dummy test')
    testEvaluateCallsGetSchemaDict() {
        const dv = this.__init()

        dv.spyOn('evaluate', () => {
            return 42
        })

        const expected = 42
        const result = dv.evaluate()

        this.assertEqual(dv.spy.evaluate.count, 1)
        this.assertEqual(expected, result)
    }

    @targets('evaluate')
    @desc('tests starting with underscore are ignored')
    @desc('@desc decorator is optional, if not used, the name of the func ' +
          'will be used instead')
    _testEvaluateCallsMaterializeSchemas() {
        // should fail if test is not ignored
        this.assertTrue(false)
    }

    __init() {
        const dv = new ClassMock(new DynamicValue())
        return dv
    }
}
