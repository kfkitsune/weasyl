'use strict';

var gulp = require('gulp');
var autoprefixer = require('gulp-autoprefixer');
var rename = require('gulp-rename');
var rev = require('gulp-rev');
var sass = require('gulp-sass');
var pump = require('pump');
var uglify = require('gulp-uglify');
var sourcemaps = require('gulp-sourcemaps');
var concat = require('gulp-concat');
var rename = require('gulp-rename');
var cssnano = require('gulp-cssnano');


// Minify and concatenate site-wide common JavaScript files
gulp.task('scripts', function (cb) {
    pump([
        // List scripts in the order they should load
        gulp.src([
            'static/scripts/jquery-3.2.1.min.js',
            // Development version of jQuery Migrate: Emits warnings to the console on use of removed/deprecated functions
            // Minimally, the imageselect script is using a deprecated function
            // 'static/scripts/jquery-migrate-3.0.0.js',
            // Production version; does not emit warnings.
            'static/scripts/jquery-migrate-3.0.0.min.js',
            'static/scripts/typeahead.bundle.min.js',
            'static/scripts/marked.js',
            'static/scripts/scripts.js',
        ]),
        sourcemaps.init(),
        concat('main.min.js'),
        uglify(),
        rename({dirname: 'scripts/'}),
        rev(),
        sourcemaps.write('.'),
        gulp.dest('build/'),
        rev.manifest('build/rev-manifest.json', {base: 'build', merge: true}),
        gulp.dest('build/')
    ], cb);
});

gulp.task('scripts:watch', function () {
    gulp.watch('static/**/*.js', ['scripts']);
});

gulp.task('sass', function (cb) {
    pump([
        gulp.src('assets/scss/site.scss'),
        sourcemaps.init(),
        sass().on('error', sass.logError),
        autoprefixer({
            browsers: ['last 2 versions', 'Android >= 4.4'],
        }),
        // Seems to be ever-so-slightly smaller than ``sass({outputStyle: 'compressed'})``
        // On the order of ~1kB
        cssnano(),
        rev(),
        rename({dirname: 'css/'}),
        sourcemaps.write('.'),
        gulp.dest('build/'),
        rev.manifest('build/rev-manifest.json', {base: 'build', merge: true}),
        gulp.dest('build/')
    ], cb);
});

gulp.task('sass:watch', function () {
    gulp.watch('assets/scss/**/*.scss', ['sass']);
});
