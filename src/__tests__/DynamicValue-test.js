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

    @targets('evaluate')
    @desc('tests aes ecb decryption')
    testEvaluateAesEcbDecryption() {
        const dv = this.__init()

        dv.message = 'AUHkSPhNLNE+Glv5Qp7lw10OtcVErtm8GC/knMwMhVeiKeA/JKSD' +
            'tfY9dGd7jEpm'
        dv.msgEnc = 'Utf8'
        dv.key = 'EY8WePvjM5GGwQzn'
        dv.keyEnc = 'Utf8'
        dv.mode = 'ECB'
        dv.pad = 'Pkcs7'

        const expected = 'e10adc3949ba59abbe56e057f20f883e'
        const result = dv.evaluate()

        this.assertEqual(expected, result)
    }

    __init() {
        const dv = new ClassMock(new DynamicValue())
        return dv
    }
}
