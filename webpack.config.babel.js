import path from 'path'
import DynamicValue from './src/DynamicValue'

if (!DynamicValue.identifier) {
    let msg = 'DynamicValue requires an identifier like: ' +
        'com.luckymarmot.PawExtensions.MySuperDynamicValue'
    throw new Error(msg)
}

const name = DynamicValue.identifier.split('.').slice(-1)

const config = {
    target: 'web',
    entry: [
        './src/DynamicValue.js'
    ],
    output: {
        path: path.join(__dirname, './dist/' + DynamicValue.identifier),
        pathInfo: true,
        publicPath: '/dist/',
        filename: name + '.js'
    },
    module: {
        loaders: [
            {
                loader: 'babel-loader',
                include: [
                    path.resolve(__dirname, 'src')
                ],
                test: /\.js$/
            },
            {
                loader: 'json-loader',
                include: [
                    path.resolve(__dirname, 'node_modules')
                ],
                test: /\.json$/
            }
        ]
    },
    node: {
        crypto: false
    },
    resolve: {
        alias: {
            crypto: require.resolve('crypto-browserify')
        }
    }
}

module.exports = config
